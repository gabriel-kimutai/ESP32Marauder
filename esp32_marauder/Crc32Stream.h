#pragma once
#ifndef Crc32Stream_h
#define Crc32Stream_h

// ----------------------------------------------------------------------------
//  Crc32Stream - CRC-32/IEEE (reflected, poly 0xEDB88320, init 0xFFFFFFFF,
//  final XOR 0xFFFFFFFF) used to protect each binary capture frame streamed
//  over serial (see Buffer::saveSerialBinary). This MUST stay byte-for-byte
//  compatible with the companion app's Crc32.kt / SerialDemux.kt, which compute
//  the CRC over the 9-byte frame header (seq+type+len) immediately followed by
//  the payload.
//
//  Header-only and free of any Arduino/ESP dependency so the native Unity test
//  suite exercises the exact same implementation that runs on the device.
// ----------------------------------------------------------------------------

#include <stddef.h>
#include <stdint.h>

namespace marauder {

// Lazily-built lookup table (identical to the one in Crc32.kt).
inline const uint32_t* crc32Table() {
  static uint32_t table[256];
  static bool built = false;
  if (!built) {
    for (uint32_t n = 0; n < 256; n++) {
      uint32_t c = n;
      for (int k = 0; k < 8; k++)
        c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      table[n] = c;
    }
    built = true;
  }
  return table;
}

// CRC-32 over `aLen` bytes of `a` followed by `bLen` bytes of `b`. Either part
// may be empty (pass a null pointer with a zero length). The two-part form
// mirrors SerialDemux.Crc32.compute(header, 0, 9, payload, payloadLen) so the
// header and payload can be CRC'd without an intermediate copy.
inline uint32_t captureFrameCrc32(const uint8_t* a, size_t aLen,
                                  const uint8_t* b, size_t bLen) {
  const uint32_t* table = crc32Table();
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < aLen; i++)
    crc = table[(crc ^ a[i]) & 0xFFu] ^ (crc >> 8);
  for (size_t i = 0; i < bLen; i++)
    crc = table[(crc ^ b[i]) & 0xFFu] ^ (crc >> 8);
  return crc ^ 0xFFFFFFFFu;
}

// Convenience single-buffer form.
inline uint32_t captureFrameCrc32(const uint8_t* data, size_t len) {
  return captureFrameCrc32(data, len, nullptr, 0);
}

}  // namespace marauder

#endif
