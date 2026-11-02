#include <unity.h>

#include <stdint.h>
#include <string.h>

#include "Crc32Stream.h"

void setUp() {}
void tearDown() {}

// The canonical CRC-32/IEEE "check" value for the ASCII string "123456789" is
// 0xCBF43926. This pins our table/algorithm to the same polynomial, init and
// final-XOR as the companion app's Crc32.kt.
void test_crc32_known_check_value() {
  const uint8_t data[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
  TEST_ASSERT_EQUAL_HEX32(
      0xCBF43926u, marauder::captureFrameCrc32(data, sizeof(data)));
}

// A full capture-frame header (seq=1 LE, type=0, len=5 LE) followed by the
// payload "hello", CRC'd with the two-part form SerialDemux uses
// (Crc32.compute(header, 0, 9, payload, payloadLen)).
void test_crc32_frame_header_plus_payload() {
  const uint8_t header[9] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00};
  const uint8_t payload[5] = {'h', 'e', 'l', 'l', 'o'};

  const uint32_t got = marauder::captureFrameCrc32(header, 9, payload, 5);
  TEST_ASSERT_EQUAL_HEX32(0xF6118C65u, got);

  // The two-part form must equal CRC over the single concatenated buffer.
  uint8_t joined[14];
  memcpy(joined, header, 9);
  memcpy(joined + 9, payload, 5);
  TEST_ASSERT_EQUAL_HEX32(got, marauder::captureFrameCrc32(joined, sizeof(joined)));
}

// A zero-length payload frame (seq=0, type=1/log, len=0) — the CRC is computed
// over the 9-byte header only.
void test_crc32_empty_payload() {
  const uint8_t header[9] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
  TEST_ASSERT_EQUAL_HEX32(
      0xDB693D1Eu, marauder::captureFrameCrc32(header, 9, nullptr, 0));
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_crc32_known_check_value);
  RUN_TEST(test_crc32_frame_header_plus_payload);
  RUN_TEST(test_crc32_empty_payload);
  return UNITY_END();
}
