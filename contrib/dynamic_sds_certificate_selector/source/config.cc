#include "contrib/dynamic_sds_certificate_selector/source/config.h"

#include <memory>

#include "envoy/registry/registry.h"
#include "envoy/ssl/handshaker.h"

#include "source/common/common/assert.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/tls/default_tls_certificate_selector.h"

#include "contrib/dynamic_sds_certificate_selector/source/dynamic_sds_certificate_selector.h"
#include "contrib/envoy/extensions/transport_sockets/tls/certificate_selectors/dynamic_sds/v3alpha/config.pb.validate.h" // IWYU pragma: keep

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {

Ssl::TlsCertificateSelectorFactory
DynamicSdsCertificateSelectorConfigFactory::createTlsCertificateSelectorFactory(
    const Protobuf::Message& config, Server::Configuration::CommonFactoryContext& factory_context,
    ProtobufMessage::ValidationVisitor& validation_visitor, absl::Status& creation_status,
    bool for_quic) {

  // Default selector fallback - also used if the config is bad
  auto default_config_factory =
      TlsCertificateSelectorConfigFactoryImpl::getDefaultTlsCertificateSelectorConfigFactory();
  const Protobuf::Any any;
  auto default_selector_factory = default_config_factory->createTlsCertificateSelectorFactory(
      any, factory_context, ProtobufMessage::getNullValidationVisitor(), creation_status, for_quic);

  if (for_quic) {
    // QUIC does not support async certificate selection
    ENVOY_LOG(error, "Dynamic SDS Certificate Selector does not support QUIC");
    return default_selector_factory;
  }
  DynamicSdsCertificateSelectorConfig typed_config;
  try {
    const auto& any_config = dynamic_cast<const Protobuf::Any&>(config);
    typed_config = MessageUtil::anyConvertAndValidate<DynamicSdsCertificateSelectorConfig>(
        any_config, validation_visitor);
  } catch (EnvoyException& e) {
    ENVOY_LOG(error, "Invalid DynamicSdsCertificateSelectorConfig: {}", e.what());
    return default_selector_factory;
  } catch (std::bad_cast& e) {
    ENVOY_LOG(error, "Invalid proto type of {}, details: {}", config.GetTypeName(), e.what());
    return default_selector_factory;
  }

  // Compile regex rules during validation
  auto rules_status = DynamicSdsCertificateSelector::compileRules(typed_config);
  if (!rules_status.ok()) {
    ENVOY_LOG(error, "Invalid selection rules: {}", rules_status.status().message());
    return default_selector_factory;
  }

  // Capture factory context resources that we need
  // The provided factory context is actually a ServerFactoryContext (not CommonFactoryContext)
  ASSERT(dynamic_cast<Server::Configuration::ServerFactoryContext*>(&factory_context) != nullptr);
  auto& server_factory_context =
      dynamic_cast<Server::Configuration::ServerFactoryContext&>(factory_context);
  auto& secret_manager = server_factory_context.secretManager();
  auto& dispatcher = factory_context.mainThreadDispatcher();
  auto& scope = factory_context.scope();

  // Return factory lambda that creates the selector instance
  // we recompile the rules in the c'tor of the selector becaue of unique_ptr lifetime issues
  // the lifetime of the factory is guranteed to be at least the lifetime of any instace created
  // from it.
  return [typed_config, &server_factory_context, default_selector_factory, &secret_manager,
          &dispatcher, &scope](const Ssl::ServerContextConfig& server_context_config,
                               Ssl::TlsCertificateSelectorContext& selector_ctx)
             -> std::unique_ptr<Ssl::TlsCertificateSelector> {
    return std::make_unique<DynamicSdsCertificateSelector>(
        typed_config, server_factory_context, default_selector_factory, server_context_config,
        selector_ctx, secret_manager, dispatcher, scope);
  };
}

/**
 * Static registration for the Dynamic SDS Certificate Selector factory.
 * This makes the extension discoverable by Envoy's extension registry.
 */
REGISTER_FACTORY(DynamicSdsCertificateSelectorConfigFactory,
                 Ssl::TlsCertificateSelectorConfigFactory);

} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
