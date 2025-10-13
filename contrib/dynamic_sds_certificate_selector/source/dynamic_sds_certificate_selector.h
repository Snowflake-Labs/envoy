#pragma once

#include <memory>
#include <string>

#include "envoy/event/dispatcher.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/server/factory_context.h"
#include "envoy/ssl/handshaker.h"
#include "envoy/stats/scope.h"

#include "source/common/common/logger.h"
#include "source/common/common/regex.h"
#include "source/common/init/manager_impl.h"
#include "source/common/init/watcher_impl.h"
#include "source/common/tls/context_impl.h"

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "contrib/dynamic_sds_certificate_selector/source/certificate_cache.h"
#include "contrib/dynamic_sds_certificate_selector/source/stats.h"
#include "contrib/envoy/extensions/transport_sockets/tls/certificate_selectors/dynamic_sds/v3alpha/config.pb.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {

using DynamicSdsCertificateSelectorConfig = envoy::extensions::transport_sockets::tls::
    certificate_selectors::dynamic_sds::v3alpha::DynamicSdsCertificateSelectorConfig;

struct DynamicSdsCallback {

  // This is called on the main thread, and immedietly dispatches to worker threads.
  void onCertificateReady(OptRef<const Ssl::TlsContext> tls_ctx) {
    // Capture by value to avoid use-after-free when DynamicSdsCallback is destroyed
    // after pending_selections_.erase() but before the lambda executes
    cb_->dispatcher().post([still_alive = still_alive_, cb = std::move(cb_),
                            cert_ready_cb = cert_ready_cb_, tls_ctx]() mutable {
      if (still_alive.expired()) {
        return;
      }
      cert_ready_cb(std::move(cb), tls_ctx);
    });
  }

  bool expired() { return still_alive_.expired(); }

  Ssl::CertificateSelectionCallbackPtr cb_;
  const std::function<void(Ssl::CertificateSelectionCallbackPtr, OptRef<const Ssl::TlsContext>)>
      cert_ready_cb_;
  const std::weak_ptr<bool> still_alive_;
};

using DynamicSdsCallbackPtr = std::unique_ptr<DynamicSdsCallback>;

struct SdsProviderState {
  const Secret::TlsCertificateConfigProviderSharedPtr provider_;
  const Common::CallbackHandlePtr handle_;
  const std::unique_ptr<Init::ManagerImpl> init_manager_;
  const std::unique_ptr<Init::WatcherImpl> watcher_;
};

/**
 * Compiled certificate selection rule with precompiled regex matcher.
 */
struct CompiledRule {
  CompiledRule(std::unique_ptr<Regex::CompiledGoogleReMatcher> matcher_arg,
               const std::string& substitution)
      : matcher(std::move(matcher_arg)), substitution(substitution) {}

  const std::unique_ptr<Regex::CompiledGoogleReMatcher> matcher;
  const std::string substitution;
};

/**
 * Dynamic SDS Certificate Selector implementation.
 *
 * This extension enables dynamic TLS certificate selection during SSL handshake
 * based on connection metadata such as SNI. It creates SDS subscriptions on-demand
 * and caches certificates for performance.
 */
class DynamicSdsCertificateSelector : public Ssl::TlsCertificateSelector,
                                      Logger::Loggable<Logger::Id::connection> {
public:
  DynamicSdsCertificateSelector(const DynamicSdsCertificateSelectorConfig& config,
                                Server::Configuration::ServerFactoryContext& server_factory_context,
                                Ssl::TlsCertificateSelectorFactory default_selector_factory,
                                const Ssl::ServerContextConfig& server_config,
                                Ssl::TlsCertificateSelectorContext& selector_ctx,
                                Secret::SecretManager& secret_manager,
                                Event::Dispatcher& mt_dispatcher, Stats::Scope& scope);

  Ssl::SelectionResult selectTlsContext(const SSL_CLIENT_HELLO& ssl_client_hello,
                                        Ssl::CertificateSelectionCallbackPtr cb) override;

  std::pair<const Ssl::TlsContext&, Ssl::OcspStapleAction>
  findTlsContext(absl::string_view, const Ssl::CurveNIDVector&, bool, bool*) override {
    RELEASE_ASSERT(
        false,
        "findTlsContext (QUIC) not implemented, and it should never be called (for_quic == false)");
  }

  /**
   * Compile regex patterns from the configuration into reusable matchers.
   * This is called during validation to ensure all patterns are valid and to
   * pre-compile them for performance during certificate selection.
   */
  static absl::StatusOr<std::vector<std::unique_ptr<CompiledRule>>>
  compileRules(const DynamicSdsCertificateSelectorConfig& config);

private:
  /**
   * Find matching certificate name using regex rules.
   * Returns the certificate name if a rule matches, empty string otherwise.
   * @param sni_value The SNI value to match against rules
   */
  std::string findMatchingCertificate(const std::string& sni_value) const;

  /**
   * Fetch a certificate asynchronously from SDS and cache it.
   * Creates a new SDS subscription if needed.
   */
  void fetchCertificateAsync(const std::string& selection_key, DynamicSdsCallbackPtr cb);

  /**
   * Transfer back control to the worker thread when the certificate is in the cache.
   * Called when SDS udpate completed, and if the secret is valid the TlsContext will be available.
   */
  void onCertificateReady(const std::string& selection_key,
                          OptRef<const Ssl::TlsContext> tls_context);

  /**
   * Delegate to default selector if enabled and available.
   */
  Ssl::SelectionResult delegateToDefaultSelector(const SSL_CLIENT_HELLO& ssl_client_hello,
                                                 Ssl::CertificateSelectionCallbackPtr cb);

  /**
   * Determine OCSP staple action based on client capabilities, policy, and certificate state.
   * Based on DefaultTlsCertificateSelector::ocspStapleAction implementation.
   *
   * @param tls_context The TLS context with certificate and OCSP response
   * @param client_ocsp_capable Whether the client supports OCSP stapling
   * @return The appropriate OCSP staple action to take
   */
  Ssl::OcspStapleAction ocspStapleAction(const Ssl::TlsContext& tls_context,
                                         bool client_ocsp_capable, SslStats& ssl_stats) const;

  const DynamicSdsCertificateSelectorConfig config_;
  std::vector<std::unique_ptr<CompiledRule>> compiled_rules_{};
  Server::Configuration::ServerFactoryContext& server_factory_context_;
  const Ssl::ServerContextConfig& server_config_;
  ServerContextImpl& server_ctx_;
  Secret::SecretManager& secret_manager_;
  Event::Dispatcher& mt_dispatcher_;
  Stats::Scope& scope_;

  // Certificate cache for performance optimization
  std::unique_ptr<CertificateCache> certificate_cache_;

  // Default certificate selector for fallback (if enabled)
  Ssl::TlsCertificateSelectorPtr fallback_selector_;

  // Pending async selections waiting for certificates
  absl::flat_hash_map<std::string, std::vector<DynamicSdsCallbackPtr>> pending_selections_;

  // Statistics for monitoring selector performance
  SelectorStats stats_;

  // Map selection keys to SDS providers to track active subscriptions and callbacks
  absl::flat_hash_map<std::string, std::unique_ptr<SdsProviderState>> sds_providers_;

  const std::shared_ptr<bool> still_alive_{std::make_shared<bool>(true)};
};

} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
