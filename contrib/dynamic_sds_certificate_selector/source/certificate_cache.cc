#include "contrib/dynamic_sds_certificate_selector/source/certificate_cache.h"

#include <chrono>
#include <memory>

#include "envoy/ssl/context.h"

#include "source/common/common/assert.h"
#include "source/common/common/fmt.h"

#include "contrib/dynamic_sds_certificate_selector/source/stats.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace DynamicSds {

CertificateCache::CertificateCache(Event::Dispatcher& dispatcher, SelectorStats& stats,
                                   const CacheConfig& config, TimeSource& time_source)
    : dispatcher_(dispatcher), stats_(stats), config_(config), time_source_(time_source) {

  UNREFERENCED_PARAMETER(dispatcher_);
  /*
  Disabling timer since we don't want to evict from cache without removing the provider (it will
  reinsert immedietly)
  TODO(igadot): implement cache eviction + figure out how to deal with updates (replacing the cert
  but not deleting the provider)

  eviction_timer_ = dispatcher_.createTimer([this]() {
    evictExpiredEntries();
    scheduleEviction();
  });

  scheduleEviction();
  */

  ENVOY_LOG(debug,
            "Certificate cache initialized with max_entries={}, ttl={}s, eviction_interval={}s",
            config_.max_cache_entries(), config_.cache_ttl().seconds(),
            config_.eviction_interval().seconds());
}

CertificateCache::~CertificateCache() {
  if (eviction_timer_) {
    eviction_timer_->disableTimer();
  }
}

CertificateEntryOptRef CertificateCache::getCertificate(const std::string& selection_key) {
  CertificateEntry* entry = nullptr;
  {
    const auto ts = time_source_.monotonicTime();
    absl::ReaderMutexLock lock(&cache_mu_);
    auto it = cache_.find(selection_key);
    if (it != cache_.end()) {
      entry = it->second.get();
      entry->last_access.store(ts);
    }
  }
  return makeOptRefFromPtr(entry);
}

void CertificateCache::putCertificate(const std::string& selection_key,
                                      std::unique_ptr<ServerContextImpl>&& server_context_impl) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  if (config_.max_cache_entries() > 0) {
    absl::ReaderMutexLock lock(&cache_mu_);
    if (cache_.size() >= config_.max_cache_entries() &&
        cache_.find(selection_key) == cache_.end()) {
      ENVOY_LOG(warn, "Certificate cache full - cannot cache certificate for key: {}",
                selection_key);
      return;
    }
  }
  auto entry = std::make_unique<CertificateEntry>(std::move(server_context_impl),
                                                  time_source_.monotonicTime());
  size_t size;
  {
    absl::WriterMutexLock lock(&cache_mu_);
    cache_[selection_key] = std::move(entry);
    size = cache_.size();
  }
  stats_.cache_size_.set(size);
  ENVOY_LOG(debug, "Certificate cached for key: {}, cache size: {}", selection_key, size);
}

void CertificateCache::evictExpiredEntries() {
  auto now = time_source_.monotonicTime();
  auto ttl = Seconds(config_.cache_ttl().seconds());

  // TODO (igadot): use read lock for checking conditions, and write lock for erasing
  absl::WriterMutexLock lock(&cache_mu_);

  auto it = cache_.begin();
  while (it != cache_.end()) {
    if (now - it->second->last_access.load() > ttl) {
      ENVOY_LOG(debug, "Evicting expired certificate cache entry for key: {}", it->first);
      // TODO (igadot): delete the cert provider? (this means the entry here should actually include
      // the provider)
      cache_.erase(it++);
      stats_.cache_evictions_ttl_.inc();
    } else {
      ++it;
    }
  }

  stats_.cache_size_.set(cache_.size());
}

void CertificateCache::scheduleEviction() {
  auto interval = std::chrono::milliseconds(config_.eviction_interval().seconds() * 1000);
  eviction_timer_->enableTimer(interval);
}

} // namespace DynamicSds
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
