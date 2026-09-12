#pragma once

#include <stdint.h>
#include <Packet.h>

#ifndef MAX_PROX_HASHES
  #define MAX_PROX_HASHES 8
#endif

#ifndef MAX_PROX_HASH_BYTES
  #define MAX_PROX_HASH_BYTES 3
#endif

#ifndef MAX_PROX_LIST_LEN
  #define MAX_PROX_LIST_LEN 48
#endif

struct ProxHashEntry {
  uint8_t len;
  uint8_t bytes[MAX_PROX_HASH_BYTES];
};

class ProximitySuppress {
  bool _enabled;
  int8_t _snr_threshold;
  uint16_t _hold_secs;
  uint8_t _num_hashes;
  ProxHashEntry _hashes[MAX_PROX_HASHES];
  unsigned long _suppress_until_ms;
  bool _suppress_active;

  bool matchesLastHop(const mesh::Packet* packet) const;
  void armSuppress(unsigned long now_ms);

public:
  ProximitySuppress();

  void clearSuppress();
  bool parseAndSetList(const char* list_str, char* err, size_t err_len);
  void setEnabled(bool enabled);
  void setSnrThreshold(int8_t snr_db);
  void setHoldSecs(uint16_t hold_secs);

  // Call on every received packet (even duplicates). Arms the timer when a
  // strong flood arrives via a listed last-hop repeater.
  void observePacket(const mesh::Packet* packet, int8_t snr_qdb, unsigned long now_ms);

  // Gate for allowPacketForward().
  bool allowForward(unsigned long now_ms);

  bool isSuppressed(unsigned long now_ms) const;
  uint32_t suppressedSecsLeft(unsigned long now_ms) const;
  void formatStatus(const char* list_str, char* reply, size_t max_len, unsigned long now_ms) const;

  bool isEnabled() const { return _enabled; }
  int8_t getSnrThreshold() const { return _snr_threshold; }
  uint16_t getHoldSecs() const { return _hold_secs; }
  uint8_t getHashCount() const { return _num_hashes; }
};
