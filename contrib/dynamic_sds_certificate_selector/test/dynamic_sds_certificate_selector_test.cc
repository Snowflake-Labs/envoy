#include <memory>

#include "source/common/stats/isolated_store_impl.h"

#include "test/mocks/init/mocks.h"
#include "test/mocks/secret/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/utility.h"

#include "contrib/dynamic_sds_certificate_selector/source/dynamic_sds_certificate_selector.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::NiceMock;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {
namespace {

class DynamicSdsCertificateSelectorTest : public ::testing::Test {
public:
  DynamicSdsCertificateSelectorTest()
      : api_(Api::createApiForTest()), stats_scope_(stats_store_.createScope("test.")),
        dispatcher_(api_->allocateDispatcher("test_thread")) {}

protected:
  void SetUp() override {
    setupConfig();
    setupMocks();
  }

  void setupConfig() {
    // Create a basic valid configuration
    const std::string yaml_config = R"EOF(
sds_source:
  api_config_source:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
    - envoy_grpc:
        cluster_name: sds_cluster
cache_config:
  cache_ttl: 3600s
  max_cache_entries: 1000
  eviction_interval: 300s
enable_default_selector_fallback: false
rules:
- sni_value_rewrite:
    pattern:
      google_re2: {}
      regex: "^([^.]+)\\.example\\.com$"
    substitution: "cert-\\1"
)EOF";

    TestUtility::loadFromYaml(yaml_config, typed_config_);
  }

  void setupMocks() {
    ON_CALL(factory_context_, secretManager()).WillByDefault(ReturnRef(secret_manager_));
    ON_CALL(factory_context_, mainThreadDispatcher()).WillByDefault(ReturnRef(*dispatcher_));
    ON_CALL(factory_context_, scope()).WillByDefault(ReturnRef(*stats_scope_));
  }

  Api::ApiPtr api_;
  Stats::IsolatedStoreImpl stats_store_;
  Stats::ScopeSharedPtr stats_scope_;
  Event::DispatcherPtr dispatcher_;

  DynamicSdsCertificateSelectorConfig typed_config_;
  NiceMock<Secret::MockSecretManager> secret_manager_;
  NiceMock<Server::Configuration::MockServerFactoryContext> factory_context_;
  // Create a simple mock context that provides getTlsContexts
  class MockTlsCertificateSelectorContext : public Ssl::TlsCertificateSelectorContext {
  public:
    MOCK_METHOD(const std::vector<Ssl::TlsContext>&, getTlsContexts, (), (const));
  };
  NiceMock<MockTlsCertificateSelectorContext> selector_ctx_;
  NiceMock<Init::MockManager> init_manager_;
};

TEST_F(DynamicSdsCertificateSelectorTest, ConfigFactoryCorrectName) {
  DynamicSdsCertificateSelectorConfigFactory factory;

  EXPECT_EQ("envoy.tls.certificate_selectors.dynamic_sds", factory.name());
}

TEST_F(DynamicSdsCertificateSelectorTest, ValidConfigurationAccepted) {
  DynamicSdsCertificateSelectorConfigFactory factory;
  ProtobufMessage::NullValidationVisitorImpl validation_visitor;
  absl::Status creation_status;

  auto selector_factory = factory.createTlsCertificateSelectorFactory(
      typed_config_, factory_context_, validation_visitor, creation_status, false);

  EXPECT_TRUE(creation_status.ok());
  EXPECT_TRUE(selector_factory);
}

TEST_F(DynamicSdsCertificateSelectorTest, InvalidConfigurationFallback) {
  DynamicSdsCertificateSelectorConfigFactory factory;
  ProtobufMessage::NullValidationVisitorImpl validation_visitor;
  absl::Status creation_status;

  // Create invalid config with no SDS sources
  DynamicSdsCertificateSelectorConfig invalid_config;
  // No sds_sources will make it invalid due to proto validation

  auto selector_factory = factory.createTlsCertificateSelectorFactory(
      invalid_config, factory_context_, validation_visitor, creation_status, false);

  EXPECT_TRUE(creation_status.ok());
  EXPECT_TRUE(selector_factory);

  auto default_selector_factory =
      TlsCertificateSelectorConfigFactoryImpl::getDefaultTlsCertificateSelectorConfigFactory()
          ->createTlsCertificateSelectorFactory(invalid_config, factory_context_,
                                                validation_visitor, creation_status, false);
  EXPECT_TRUE(typeid(selector_factory) == typeid(default_selector_factory));
}

} // namespace
} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
