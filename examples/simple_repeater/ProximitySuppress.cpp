#include "ProximitySuppress.h"

#include <Arduino.h>
#include <Utils.h>
#include <helpers/TxtDataHelpers.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

ProximitySuppress::ProximitySuppress() {
  _enabled = false;
  _snr_threshold = 8;
  _hold_secs = 600;
  _num_hashes = 0;
  _suppress_until_ms = 0;
  _suppress_active = false;
  memset(_hashes, 0, sizeof(_hashes));
}

void ProximitySuppress::clearSuppress() {
  _suppress_active = false;
  _suppress_until_ms = 0;
}

void ProximitySuppress::setEnabled(bool enabled) {
  _enabled = enabled;
  if (!_enabled) clearSuppress();
}

void ProximitySuppress::setSnrThreshold(int8_t snr_db) {
  _snr_threshold = snr_db;
}

void ProximitySuppress::setHoldSecs(uint16_t hold_secs) {
  _hold_secs = hold_secs;
}

static bool parseHashToken(const char* tok, ProxHashEntry& out) {
  const char* hex = tok;
  if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
  size_t slen = strlen(hex);
  if (slen != 2 && slen != 4 && slen != 6) return false;
  out.len = (uint8_t)(slen / 2);
  memset(out.bytes, 0, MAX_PROX_HASH_BYTES);
  return mesh::Utils::fromHex(out.bytes, out.len, hex);
}

bool ProximitySuppress::parseAndSetList(const char* list_str, char* err, size_t err_len) {
  _num_hashes = 0;
  memset(_hashes, 0, sizeof(_hashes));

  if (list_str == NULL || list_str[0] == 0) {
    clearSuppress();
    return true;
  }

  char buf[MAX_PROX_LIST_LEN];
  StrHelper::strncpy(buf, list_str, sizeof(buf));

  char* cursor = buf;
  while (*cursor) {
    if (_num_hashes >= MAX_PROX_HASHES) {
      snprintf(err, err_len, "Err - too many prox hashes");
      _num_hashes = 0;
      return false;
    }

    while (*cursor == ' ' || *cursor == ',') cursor++;
    if (*cursor == 0) break;

    char* end = cursor;
    while (*end && *end != ',') end++;
    char saved = *end;
    *end = 0;

    if (!parseHashToken(cursor, _hashes[_num_hashes])) {
      snprintf(err, err_len, "Err - bad prox hash (use 2/4/6 hex chars)");
      _num_hashes = 0;
      return false;
    }
    _num_hashes++;

    *end = saved;
    cursor = (saved == 0) ? end : end + 1;
  }

  clearSuppress();
  return true;
}

bool ProximitySuppress::matchesLastHop(const mesh::Packet* packet) const {
  if (_num_hashes == 0) return false;

  uint8_t n = packet->getPathHashCount();
  if (n == 0) return false;

  uint8_t sz = packet->getPathHashSize();
  const uint8_t* last_hop = &packet->path[(n - 1) * sz];
  for (uint8_t i = 0; i < _num_hashes; i++) {
    if (_hashes[i].len == sz && memcmp(last_hop, _hashes[i].bytes, sz) == 0) {
      return true;
    }
  }
  return false;
}

void ProximitySuppress::armSuppress(unsigned long now_ms) {
  _suppress_active = true;
  _suppress_until_ms = now_ms + (unsigned long)_hold_secs * 1000UL;
}

bool ProximitySuppress::isSuppressed(unsigned long now_ms) const {
  if (!_suppress_active) return false;
  // Overflow-safe: still within hold window?
  if ((long)(now_ms - _suppress_until_ms) < 0) return true;
  return false;
}

void ProximitySuppress::observePacket(const mesh::Packet* packet, int8_t snr_qdb, unsigned long now_ms) {
  if (!_enabled || _num_hashes == 0) return;
  if (!packet->isRouteFlood()) return;
  if (packet->getPathHashCount() < 1) return;

  int8_t snr_db = snr_qdb / 4;
  if (snr_db < _snr_threshold) return;
  if (!matchesLastHop(packet)) return;

  armSuppress(now_ms);
  MESH_DEBUG_PRINTLN("prox: armed suppress for %us (snr=%d)", (unsigned)_hold_secs, (int)snr_db);
}

bool ProximitySuppress::allowForward(unsigned long now_ms) {
  if (!_enabled || _num_hashes == 0) return true;

  if (isSuppressed(now_ms)) return false;

  // Timer expired — clear sticky flag
  if (_suppress_active) {
    _suppress_active = false;
    MESH_DEBUG_PRINTLN("prox: suppress expired");
  }
  return true;
}

uint32_t ProximitySuppress::suppressedSecsLeft(unsigned long now_ms) const {
  if (!isSuppressed(now_ms)) return 0;
  return (uint32_t)((_suppress_until_ms - now_ms + 999UL) / 1000UL);
}

void ProximitySuppress::formatStatus(const char* list_str, char* reply, size_t max_len, unsigned long now_ms) const {
  int n = snprintf(reply, max_len, "> %s snr:%d hold:%us list:%s hashes:%u",
                   _enabled ? "on" : "off",
                   (int)_snr_threshold,
                   (unsigned)_hold_secs,
                   (list_str && list_str[0]) ? list_str : "-",
                   (unsigned)_num_hashes);
  if (n < 0) return;
  if (isSuppressed(now_ms) && (size_t)n < max_len) {
    snprintf(reply + n, max_len - n, " suppressed:%us", (unsigned)suppressedSecsLeft(now_ms));
  }
}
