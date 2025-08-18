#pragma once

#include "envoy/common/exception.h"
#include "envoy/server/transport_socket_config.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {

#define DUMMY_METHOD(method_name)                                                                  \
  auto method_name()                                                                               \
      -> decltype(Server::Configuration::TransportSocketFactoryContext::method_name()) override {  \
    throw EnvoyException("DummyTransportSocketFactoryContext::" #method_name                       \
                         " should not be called");                                                 \
  }

/**
 * Dummy adapter that wraps a ServerFactoryContext and provides a minimal
 * TransportSocketFactoryContext interface. This is used when we need to pass
 * a TransportSocketFactoryContext but don't actually need the transport socket
 * factory functionality (only the ServerFactoryContext).
 *
 * All methods will throw an EnvoyException.
 */
class DummyTransportSocketFactoryContext
    : public Server::Configuration::TransportSocketFactoryContext {
public:
  // All other methods should not be called - add assertions
  DUMMY_METHOD(serverFactoryContext);
  DUMMY_METHOD(messageValidationVisitor);
  DUMMY_METHOD(initManager);
  DUMMY_METHOD(scope);
  DUMMY_METHOD(statsScope);
};

} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
