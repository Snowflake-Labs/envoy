#pragma once

#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {

/**
 * All stats for the Dynamic SDS Certificate Selector. @see stats_macros.h
 */
#define ALL_DYNAMIC_SDS_SELECTOR_STATS(COUNTER, GAUGE, HISTOGRAM)                                  \
  COUNTER(cache_hits)             /* Successful cache lookups */                                   \
  COUNTER(cache_misses)           /* Cache lookup failures */                                      \
  COUNTER(async_selections)       /* Async certificate selections initiated */                     \
  COUNTER(default_selector_used)  /* Default selector fallback uses */                             \
  COUNTER(selection_failures)     /* Total selection failures (fallback not used) */               \
  COUNTER(cache_evictions_ttl)    /* Evictions due to TTL expiration */                            \
  COUNTER(invalid_selection_keys) /* Could not extract selection key from sni */                   \
  COUNTER(sds_errors) /* Fetching a certificate from SDS failed (e.g. the certificate does not     \
                         exist) */                                                                 \
  GAUGE(cache_size, Accumulate)               /* Current certificates cached */                    \
  GAUGE(pending_async_selections, Accumulate) /* Pending async selections count */                 \
  HISTOGRAM(selection_latency,                                                                     \
            Milliseconds) /* Certificate selection time in ms (only if not in cache) */

/**
 * Struct definition for all Dynamic SDS Certificate Selector stats.
 * @see stats_macros.h
 */
struct SelectorStats {
  ALL_DYNAMIC_SDS_SELECTOR_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT,
                                 GENERATE_HISTOGRAM_STRUCT)
};

/**
 * Generate the selector stats from a stats scope.
 */
inline SelectorStats generateSelectorStats(Stats::Scope& scope) {
  return SelectorStats{ALL_DYNAMIC_SDS_SELECTOR_STATS(POOL_COUNTER(scope), POOL_GAUGE(scope),
                                                      POOL_HISTOGRAM(scope))};
}

} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
