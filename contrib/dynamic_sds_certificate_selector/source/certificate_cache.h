#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "envoy/common/optref.h"
#include "envoy/event/dispatcher.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/handshaker.h"
#include "envoy/stats/scope.h"

#include "source/common/common/logger.h"
#include "source/common/tls/server_context_impl.h"

#include "absl/container/flat_hash_map.h"
#include "absl/types/optional.h"
#include "contrib/dynamic_sds_certificate_selector/source/stats.h"
#include "contrib/envoy/extensions/transport_sockets/tls/certificate_selectors/dynamic_sds/v3alpha/config.pb.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {

using CacheConfig = envoy::extensions::transport_sockets::tls::certificate_selectors::dynamic_sds::
    v3alpha::CacheConfig;

/**
 * Certificate cache entry representing a cached TLS certificate and its metadata.
 */
struct CertificateEntry {
  // The actual SSL context ready for use in TLS handshake
  const std::unique_ptr<ServerContextImpl> server_context_impl;

  // Timestamp when this certificate was cached
  const MonotonicTime created_at;

  // Timestamp when this entry was last accessed for LRU eviction
  mutable std::atomic<MonotonicTime> last_access;

  CertificateEntry(std::unique_ptr<ServerContextImpl> server_context_impl, MonotonicTime created_at)
      : server_context_impl(std::move(server_context_impl)), created_at(created_at),
        last_access(created_at) {}
};

using CertificateEntryOptRef = OptRef<CertificateEntry>;

/**
 * Certificate cache for storing and managing dynamically fetched certificates.
 */
class CertificateCache : Logger::Loggable<Logger::Id::connection> {
public:
  CertificateCache(Event::Dispatcher& dispatcher, SelectorStats& stats, const CacheConfig& config,
                   TimeSource& time_source);

  ~CertificateCache();

  /**
   * Retrieve a certificate by selection key (e.g., SNI, client IP).
   * Updates access statistics for LRU management.
   * @param selection_key The key used to identify the certificate
   * @return Optional reference to the TLS context if found
   */
  CertificateEntryOptRef getCertificate(const std::string& selection_key);

  /**
   * Store a certificate in the cache with the given selection key.
   * May trigger eviction if cache is full.
   * @param selection_key The key to associate with this certificate
   * @param server_context_impl The server context that holds the Ssl::TlsCtx with this certificate
   */
  void putCertificate(const std::string& selection_key,
                      std::unique_ptr<ServerContextImpl>&& server_context_impl);

private:
  void evictExpiredEntries();
  void scheduleEviction();

  Event::Dispatcher& dispatcher_;
  SelectorStats& stats_;
  const CacheConfig config_;
  TimeSource& time_source_;
  absl::Mutex cache_mu_;
  absl::flat_hash_map<std::string, std::unique_ptr<CertificateEntry>>
      cache_ ABSL_GUARDED_BY(cache_mu_);
  // Timer for periodic eviction of expired entries
  Event::TimerPtr eviction_timer_;
};

} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
