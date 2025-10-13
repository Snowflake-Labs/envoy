#pragma once

#include <memory>
#include <string>

#include "envoy/server/factory_context.h"
#include "envoy/ssl/handshaker.h"

#include "source/common/common/logger.h"

#include "absl/status/status.h"
#include "contrib/envoy/extensions/transport_sockets/tls/certificate_selectors/dynamic_sds/v3alpha/config.pb.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {

using DynamicSdsCertificateSelectorConfig = envoy::extensions::transport_sockets::tls::
    certificate_selectors::dynamic_sds::v3alpha::DynamicSdsCertificateSelectorConfig;

/**
 * Config factory for Dynamic SDS Certificate Selector.
 */
class DynamicSdsCertificateSelectorConfigFactory : public Ssl::TlsCertificateSelectorConfigFactory,
                                                   Logger::Loggable<Logger::Id::config> {
public:
  // Ssl::TlsCertificateSelectorConfigFactory
  Ssl::TlsCertificateSelectorFactory
  createTlsCertificateSelectorFactory(const Protobuf::Message& config,
                                      Server::Configuration::CommonFactoryContext& factory_context,
                                      ProtobufMessage::ValidationVisitor& validation_visitor,
                                      absl::Status& creation_status, bool for_quic) override;

  std::string name() const override { return "envoy.tls.certificate_selectors.dynamic_sds"; }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<DynamicSdsCertificateSelectorConfig>();
  }
};

DECLARE_FACTORY(DynamicSdsCertificateSelectorConfigFactory);

} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
