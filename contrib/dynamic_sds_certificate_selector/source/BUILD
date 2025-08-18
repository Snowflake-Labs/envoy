load("//bazel:envoy_build_system.bzl", "envoy_cc_contrib_extension", "envoy_cc_library", "envoy_contrib_package")

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_library(
    name = "dynamic_sds_certificate_selector",
    srcs = [
        "certificate_cache.cc",
        "dynamic_sds_certificate_selector.cc",
    ],
    hdrs = [
        "certificate_cache.h",
        "dummy_transport_socket_factory_context.h",
        "dynamic_sds_certificate_selector.h",
        "server_context_config_adapter.h",
        "stats.h",
    ],
    deps = [
        "//envoy/event:dispatcher_interface",
        "//envoy/init:manager_interface",
        "//envoy/secret:secret_manager_interface",
        "//envoy/server:factory_context_interface",
        "//envoy/ssl:handshaker_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//source/common/common:assert_lib",
        "//source/common/common:logger_lib",
        "//source/common/secret:secret_manager_impl_lib",
        "//source/common/tls:server_context_lib",
        "//source/common/tls:utility_lib",
        "@envoy_api//contrib/envoy/extensions/transport_sockets/tls/certificate_selectors/dynamic_sds/v3alpha:pkg_cc_proto",
        "@envoy_api//envoy/type/matcher/v3:pkg_cc_proto",
    ],
)

envoy_cc_contrib_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":dynamic_sds_certificate_selector",
        "//envoy/registry",
        "//envoy/ssl:handshaker_interface",
        "@envoy_api//contrib/envoy/extensions/transport_sockets/tls/certificate_selectors/dynamic_sds/v3alpha:pkg_cc_proto",
    ],
)
