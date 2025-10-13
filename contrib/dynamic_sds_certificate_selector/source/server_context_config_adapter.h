#pragma once

#include <memory>
#include <vector>

#include "envoy/ssl/context_config.h"
#include "envoy/ssl/handshaker.h"
#include "envoy/ssl/tls_certificate_config.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {

#define DELEGATE_METHOD(method_name)                                                               \
  auto method_name() const -> decltype(Ssl::ServerContextConfig::method_name()) override {         \
    return base_config_.method_name();                                                             \
  }

/**
 * Lightweight adapter that wraps a single TlsCertificateConfig and provides
 * minimal ServerContextConfig interface for creating ServerContext instances.
 * This is used to create isolated SSL contexts for individual certificates
 * in the dynamic SDS certificate selector.
 */
class ServerContextConfigAdapter : public Ssl::ServerContextConfig {
public:
  /**
   * Constructor that wraps a TlsCertificateConfig with minimal context.
   * @param tls_cert_config The certificate configuration to wrap
   * @param base_config Reference ServerContextConfig to delegate most calls to
   */
  ServerContextConfigAdapter(Ssl::TlsCertificateConfig& tls_cert_config,
                             const Ssl::ServerContextConfig& base_config)
      : tls_cert_config_(tls_cert_config), base_config_(base_config) {}

  // Return only our single certificate
  std::vector<std::reference_wrapper<const Ssl::TlsCertificateConfig>>
  tlsCertificates() const override {
    std::vector<std::reference_wrapper<const Ssl::TlsCertificateConfig>> configs;
    configs.push_back(tls_cert_config_);
    return configs;
  }

  void setSecretUpdateCallback(std::function<absl::Status()>) override {
    // No-op: This adapter wraps a static certificate, callbacks are handled by the base config
    ASSERT(false);
  }

  // Return a no-op factory since the resulting ServerContext is only used for TlsContext objects
  Ssl::TlsCertificateSelectorFactory tlsCertificateSelectorFactory() const override {
    return [](const Ssl::ServerContextConfig&,
              Ssl::TlsCertificateSelectorContext&) -> std::unique_ptr<Ssl::TlsCertificateSelector> {
      return nullptr;
    };
  }

  DELEGATE_METHOD(alpnProtocols);
  DELEGATE_METHOD(cipherSuites);
  DELEGATE_METHOD(ecdhCurves);
  DELEGATE_METHOD(signatureAlgorithms);
  DELEGATE_METHOD(certificateValidationContext);
  DELEGATE_METHOD(minProtocolVersion);
  DELEGATE_METHOD(maxProtocolVersion);
  DELEGATE_METHOD(isReady);
  DELEGATE_METHOD(createHandshaker);
  DELEGATE_METHOD(capabilities);
  DELEGATE_METHOD(sslctxCb);
  DELEGATE_METHOD(tlsKeyLogLocal);
  DELEGATE_METHOD(tlsKeyLogRemote);
  DELEGATE_METHOD(tlsKeyLogPath);
  DELEGATE_METHOD(accessLogManager);
  DELEGATE_METHOD(compliancePolicy);
  DELEGATE_METHOD(requireClientCertificate);
  DELEGATE_METHOD(ocspStaplePolicy);
  DELEGATE_METHOD(sessionTicketKeys);
  DELEGATE_METHOD(sessionTimeout);
  DELEGATE_METHOD(disableStatelessSessionResumption);
  DELEGATE_METHOD(disableStatefulSessionResumption);
  DELEGATE_METHOD(fullScanCertsOnSNIMismatch);
  DELEGATE_METHOD(preferClientCiphers);

private:
  // The wrapped certificate configuration
  const Ssl::TlsCertificateConfig& tls_cert_config_;

  // Base configuration to delegate most functionality to
  const Ssl::ServerContextConfig& base_config_;
};

} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
