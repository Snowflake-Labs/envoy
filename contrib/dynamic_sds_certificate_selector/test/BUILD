load("//bazel:envoy_build_system.bzl", "envoy_cc_test", "envoy_contrib_package")

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_test(
    name = "dynamic_sds_certificate_selector_test",
    srcs = ["dynamic_sds_certificate_selector_test.cc"],
    deps = [
        "//contrib/dynamic_sds_certificate_selector/source:config",
        "//source/common/config:utility_lib",
        "//source/common/event:dispatcher_lib",
        "//source/common/stats:isolated_store_lib",
        "//test/common/tls:ssl_test_utils",
        "//test/mocks/event:event_mocks",
        "//test/mocks/init:init_mocks",
        "//test/mocks/secret:secret_mocks",
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/ssl:ssl_mocks",
        "//test/test_common:environment_lib",
        "//test/test_common:utility_lib",
    ],
)
