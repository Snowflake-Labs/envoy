#include "contrib/dynamic_sds_certificate_selector/source/dynamic_sds_certificate_selector.h"

#include <chrono>
#include <memory>

#include "envoy/ssl/context.h"
#include "envoy/type/matcher/v3/regex.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/regex.h"
#include "source/common/init/manager_impl.h"
#include "source/common/ssl/tls_certificate_config_impl.h"
#include "source/common/tls/default_tls_certificate_selector.h"

#include "contrib/dynamic_sds_certificate_selector/source/certificate_cache.h"
#include "contrib/dynamic_sds_certificate_selector/source/dummy_transport_socket_factory_context.h"
#include "contrib/dynamic_sds_certificate_selector/source/server_context_config_adapter.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {

DynamicSdsCertificateSelector::DynamicSdsCertificateSelector(
    const DynamicSdsCertificateSelectorConfig& config,
    Server::Configuration::ServerFactoryContext& server_factory_context,
    Ssl::TlsCertificateSelectorFactory default_selector_factory,
    const Ssl::ServerContextConfig& server_config, Ssl::TlsCertificateSelectorContext& selector_ctx,
    Secret::SecretManager& secret_manager, Event::Dispatcher& mt_dispatcher, Stats::Scope& scope)
    : config_(config), server_factory_context_(server_factory_context),
      server_config_(server_config), server_ctx_(dynamic_cast<ServerContextImpl&>(selector_ctx)),
      secret_manager_(secret_manager), mt_dispatcher_(mt_dispatcher), scope_(scope),
      stats_(generateSelectorStats(scope)) {

  // Initialize certificate cache
  certificate_cache_ = std::make_unique<CertificateCache>(
      mt_dispatcher, stats_, config.cache_config(), server_factory_context.timeSource());

  // Create fallback selector if enabled
  if (config_.enable_default_selector_fallback()) {
    fallback_selector_ = default_selector_factory(server_config, selector_ctx);
  }

  auto rules_status = DynamicSdsCertificateSelector::compileRules(config);
  if (rules_status.ok()) {
    compiled_rules_ = std::move(rules_status.value());
  } else {
    IS_ENVOY_BUG(fmt::format("Passed invalid selection rules config to selector: {}",
                             rules_status.status().message()));
  }

  ENVOY_LOG(info,
            "Dynamic SDS Certificate Selector initialized with {} compiled rules, cache_ttl={}s",
            compiled_rules_.size(), config_.cache_config().cache_ttl().seconds());
}

Ssl::SelectionResult
DynamicSdsCertificateSelector::selectTlsContext(const SSL_CLIENT_HELLO& ssl_client_hello,
                                                Ssl::CertificateSelectionCallbackPtr cb) {

  // Extract SNI from ClientHello (rules are SNI-based)
  const char* sni_ptr = SSL_get_servername(ssl_client_hello.ssl, TLSEXT_NAMETYPE_host_name);
  if (sni_ptr == nullptr) {
    ENVOY_LOG(debug, "No SNI in ClientHello, trying fallback");
    return delegateToDefaultSelector(ssl_client_hello, std::move(cb));
  }

  std::string sni_value(sni_ptr);

  // Find matching certificate using regex rules
  // TODO (igadot): [future] currently all of our certs are RSA, which all clients support - to add
  // ECDSA support, need to findMatchingCertificate according to client capabilities (see
  // default_tls_certificate_selector.cc)
  std::string cert_name = findMatchingCertificate(sni_value);

  if (cert_name.empty()) {
    stats_.invalid_selection_keys_.inc();
    ENVOY_LOG(debug, "No matching certificate for SNI: {}, trying fallback", sni_value);
    return delegateToDefaultSelector(ssl_client_hello, std::move(cb));
  }

  ENVOY_LOG(trace, "Certificate selection for SNI: {} -> cert: {}", sni_value, cert_name);
  const bool client_ocsp_capable = server_ctx_.isClientOcspCapable(ssl_client_hello);
  auto& ssl_stats = server_ctx_.stats();
  if (client_ocsp_capable) {
    ssl_stats.ocsp_staple_requests_.inc();
  }

  auto cached_context = certificate_cache_->getCertificate(cert_name);
  if (cached_context.has_value()) {
    stats_.cache_hits_.inc();

    ENVOY_LOG(trace, "Certificate selection cache hit for cert: {}", cert_name);

    // Handle OCSP stapling for cached certificate
    const auto& tls_context = cached_context->server_context_impl->getTlsContexts()[0];
    auto ocsp_action = ocspStapleAction(tls_context, client_ocsp_capable, ssl_stats);

    if (ocsp_action == Ssl::OcspStapleAction::Fail) {
      ENVOY_LOG(debug, "OCSP staple policy failure for cert: {}", cert_name);
      return {Ssl::SelectionResult::SelectionStatus::Failed, nullptr, false};
    }
    return {Ssl::SelectionResult::SelectionStatus::Success, &tls_context,
            ocsp_action == Ssl::OcspStapleAction::Staple};
  }
  stats_.cache_misses_.inc();

  // Cache miss - initiate async fetch
  stats_.async_selections_.inc();
  stats_.pending_async_selections_.inc();

  auto start_time = server_factory_context_.timeSource().monotonicTime();

  // This is the logic for continuing the handshake back on this thread
  // liveness check will happen before invoking the callback back on this thread
  auto cert_ready_cb = [this, client_ocsp_capable, cert_name,
                        start_time](Ssl::CertificateSelectionCallbackPtr cb,
                                    OptRef<const Ssl::TlsContext> tls_ctx) {
    stats_.pending_async_selections_.dec();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        server_factory_context_.timeSource().monotonicTime() - start_time);
    stats_.selection_latency_.recordValue(duration.count());

    if (!tls_ctx.has_value()) {
      ENVOY_LOG(debug, "Empty TLS context for cert: {}", cert_name);
      cb->onCertificateSelectionResult({}, false);
      return;
    }
    auto ocsp_action = ocspStapleAction(*tls_ctx, client_ocsp_capable, server_ctx_.stats());
    if (ocsp_action == Ssl::OcspStapleAction::Fail) {
      ENVOY_LOG(debug, "OCSP staple policy failure for cert: {}", cert_name);
      cb->onCertificateSelectionResult({}, false);
      return;
    }
    cb->onCertificateSelectionResult(tls_ctx, ocsp_action == Ssl::OcspStapleAction::Staple);
  };

  auto mt_cb = std::make_unique<DynamicSdsCallback>(std::move(cb), std::move(cert_ready_cb),
                                                    std::weak_ptr<bool>(still_alive_));

  mt_dispatcher_.post([this, cert_name, mt_cb = std::move(mt_cb)]() mutable {
    // The selector may have been destroyed (only happens if the handshake is cancelled)
    if (mt_cb->expired()) {
      return;
    }
    fetchCertificateAsync(cert_name, std::move(mt_cb));
  });

  ENVOY_LOG(trace, "Certificate selection pending for cert: {}", cert_name);
  return {Ssl::SelectionResult::SelectionStatus::Pending, nullptr, false};
}

std::string
DynamicSdsCertificateSelector::findMatchingCertificate(const std::string& sni_value) const {
  for (const auto& rule : compiled_rules_) {
    if (rule->matcher->match(sni_value)) {
      // Apply substitution to get certificate name
      std::string cert_name = rule->matcher->replaceAll(sni_value, rule->substitution);
      ENVOY_LOG(trace, "SNI '{}' matches pattern, using certificate: {}", sni_value, cert_name);
      return cert_name;
    }
  }

  ENVOY_LOG(trace, "No matching certificate rule found for SNI: {}", sni_value);
  return EMPTY_STRING;
}

void DynamicSdsCertificateSelector::fetchCertificateAsync(const std::string& cert_name,
                                                          DynamicSdsCallbackPtr cb) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();

  auto [it, already_exists] = pending_selections_.try_emplace(cert_name);
  it->second.push_back(std::move(cb));
  if (!already_exists) {
    ENVOY_LOG(trace, "Added to pending selection queue for cert: {}", cert_name);
    return;
  }

  // We may already have the certificate in the cache - e.g. if a new connection arrives during
  // handling of a callback in the main thread
  auto cached_context = certificate_cache_->getCertificate(cert_name);
  if (cached_context.has_value()) {
    ENVOY_LOG(trace, "main thread: Certificate already cached for cert: {}", cert_name);
    onCertificateReady(cert_name,
                       makeOptRef(cached_context->server_context_impl->getTlsContexts()[0]));
    return;
  }

  // If a provider exists, either there are pending selections, or the certificate is in the cache.
  // The provider should always be destroyed before a certificate is removed from the cache
  ASSERT(!sds_providers_.contains(cert_name),
         fmt::format("provider for cert {} already exists", cert_name));

  // Use a per-secret init manager so handshake continues on update failure (see
  // SdsApi::onConfigUpdate* methods) e.g. when xDS server returns an empty response - we want to
  // remove the provider
  auto init_manager = std::make_unique<Init::ManagerImpl>(cert_name);
  auto provider = secret_manager_.findOrCreateTlsCertificateProvider(
      config_.sds_source(), cert_name, server_factory_context_, *init_manager);

  // See ContextConfigImpl::setSecretUpdateCallback for inspiration
  // Called every time the secret is updated
  auto handle = provider->addUpdateCallback([this, cert_name, provider]() -> absl::Status {
    auto tls_cert = provider->secret();
    ASSERT(tls_cert != nullptr); // see SdsApi::onConfigUpdate, should never be null
    if (tls_cert->has_private_key_provider()) {
      return absl::UnimplementedError(
          "On-demand certificates with private key provider are not supported");
    }
    // Create a dummy TransportSocketFactoryContext wrapper since TlsCertificateConfigImpl requires
    // it We checked above that there are no private key providers, so the transport socket
    // functionality won't be used
    static auto dummy_transport_context = DummyTransportSocketFactoryContext();
    auto config_or_error = Ssl::TlsCertificateConfigImpl::create(
        *tls_cert, dummy_transport_context, server_factory_context_.api(), cert_name);
    if (auto& status = config_or_error.status(); !status.ok()) {
      ENVOY_LOG(error, "Failed to create TlsCertificateConfig for cert: {}", cert_name);
      return status;
    }

    // Create a lightweight adapter config that wraps only the specific TLS certificate
    // This allows us to create an isolated ServerContext for this certificate
    auto adapter_config = ServerContextConfigAdapter(config_or_error.value(), server_config_);

    // Create ServerContextImpl using the adapter config
    // server_names is used for session resumption hash - use the secret name instead
    auto ctx_or_error = ServerContextImpl::create(scope_, std::move(adapter_config), {cert_name},
                                                  server_factory_context_, nullptr);
    if (auto& status = ctx_or_error.status(); !status.ok()) {
      ENVOY_LOG(error, "Failed to create ServerContextImpl for cert: {}", cert_name);
      return status;
    }

    auto& server_context_impl = ctx_or_error.value();

    ASSERT(server_context_impl->getTlsContexts().size() == 1);
    certificate_cache_->putCertificate(cert_name, std::move(server_context_impl));
    return absl::OkStatus();
  });

  // logic for when the secret fetch is completed for the first time (called after the update
  // callback above)
  auto cert_ready_watcher = std::make_unique<Init::WatcherImpl>(cert_name, [this, cert_name] {
    auto cached_context = certificate_cache_->getCertificate(cert_name);
    if (cached_context.has_value()) {
      onCertificateReady(cert_name, {cached_context->server_context_impl->getTlsContexts()[0]});
    } else {
      // This means the initial fetch failed - remove the provider since it most likely means cert
      // doesn't exist
      auto removed = sds_providers_.erase(cert_name);
      ASSERT(removed == 1);
      // TODO (igadot): [future] think of how to evict outdated secrets from cache (or just TTL)
      stats_.sds_errors_.inc();
      onCertificateReady(cert_name, {});
    }
  });

  // This will initiate the SDS subscription
  init_manager->initialize(*cert_ready_watcher);

  // we checked earlier that this should succeed
  RELEASE_ASSERT(
      sds_providers_
          .try_emplace(cert_name, std::make_unique<SdsProviderState>(
                                      std::move(provider), std::move(handle),
                                      std::move(init_manager), std::move(cert_ready_watcher)))
          .second,
      "sds_providers map already contains cert_name");
}

void DynamicSdsCertificateSelector::onCertificateReady(const std::string& cert_name,
                                                       OptRef<const Ssl::TlsContext> tls_context) {

  auto pending_cbs = pending_selections_.find(cert_name);
  if (pending_cbs != pending_selections_.end()) {
    for (auto& cb : pending_cbs->second) {
      // Each callback dispatches the work to the correct worker
      cb->onCertificateReady(tls_context);
    }
    pending_selections_.erase(pending_cbs);
  }
}

Ssl::SelectionResult
DynamicSdsCertificateSelector::delegateToDefaultSelector(const SSL_CLIENT_HELLO& ssl_client_hello,
                                                         Ssl::CertificateSelectionCallbackPtr cb) {

  if (config_.enable_default_selector_fallback()) {
    if (fallback_selector_) {
      stats_.default_selector_used_.inc();
      ENVOY_LOG(debug, "Delegating to default certificate selector");
      return fallback_selector_->selectTlsContext(ssl_client_hello, std::move(cb));
    }
  }

  stats_.selection_failures_.inc();
  return {Ssl::SelectionResult::SelectionStatus::Failed, nullptr, false};
}

Ssl::OcspStapleAction DynamicSdsCertificateSelector::ocspStapleAction(
    const Ssl::TlsContext& tls_context, bool client_ocsp_capable, SslStats& ssl_stats) const {

  if (!client_ocsp_capable) {
    return Ssl::OcspStapleAction::ClientNotCapable;
  }

  auto& response = tls_context.ocsp_response_;

  // Get the OCSP staple policy from server config
  auto policy = server_config_.ocspStaplePolicy();

  // Check if the certificate has the must-staple extension - upgrade policy to match
  if (tls_context.is_must_staple_) {
    policy = Ssl::ServerContextConfig::OcspStaplePolicy::MustStaple;
  }

  const bool valid_response = response && !response->isExpired();

  const auto ocsp_action = [&] {
    switch (policy) {
    case Ssl::ServerContextConfig::OcspStaplePolicy::LenientStapling:
      if (!valid_response) {
        return Ssl::OcspStapleAction::NoStaple;
      }
      return Ssl::OcspStapleAction::Staple;

    case Ssl::ServerContextConfig::OcspStaplePolicy::StrictStapling:
      if (valid_response) {
        return Ssl::OcspStapleAction::Staple;
      }
      if (response) {
        // Expired response.
        return Ssl::OcspStapleAction::Fail;
      }
      return Ssl::OcspStapleAction::NoStaple;

    case Ssl::ServerContextConfig::OcspStaplePolicy::MustStaple:
      if (!valid_response) {
        return Ssl::OcspStapleAction::Fail;
      }
      return Ssl::OcspStapleAction::Staple;
      PANIC_DUE_TO_CORRUPT_ENUM;
    }
  }();
  // Handle OCSP policy failures

  switch (ocsp_action) {
  case Ssl::OcspStapleAction::Staple:
    ssl_stats.ocsp_staple_responses_.inc();
    break;
  case Ssl::OcspStapleAction::NoStaple:
    ssl_stats.ocsp_staple_omitted_.inc();
    break;
  case Ssl::OcspStapleAction::Fail:
    ssl_stats.ocsp_staple_failed_.inc();
  case Ssl::OcspStapleAction::ClientNotCapable:
    // Client doesn't support OCSP, no action needed
    break;
  }
  return ocsp_action;
}

absl::StatusOr<std::vector<std::unique_ptr<CompiledRule>>>
DynamicSdsCertificateSelector::compileRules(const DynamicSdsCertificateSelectorConfig& config) {

  std::vector<std::unique_ptr<CompiledRule>> result{};
  for (const auto& rule : config.rules()) {
    const auto& rewrite_config = rule.sni_value_rewrite();
    const auto& pattern = rewrite_config.pattern();

    // Compile regex pattern
    auto regex_matcher = Regex::CompiledGoogleReMatcher::create(pattern);
    if (!regex_matcher.ok()) {
      return regex_matcher.status();
    }

    // Create compiled rule with matcher and substitution
    result.emplace_back(std::make_unique<CompiledRule>(std::move(regex_matcher.value()),
                                                       rewrite_config.substitution()));
  }

  ENVOY_LOG(trace, "Dynamic SDS Certificate Selector compiled {} rules", result.size());
  return result;
}

} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
