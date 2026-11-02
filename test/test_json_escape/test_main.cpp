#include <unity.h>

#include <stdint.h>
#include <string>

#include "JsonEscape.h"

void setUp() {}
void tearDown() {}

static std::string esc(const std::string& in) { return marauder::jsonEscape(in); }

// " and \ get backslash-escaped so the result is always a valid JSON string.
void test_escapes_quote_and_backslash() {
  // input bytes:  a " b \ c   ->   a \" b \\ c
  const std::string in = "a\"b\\c";
  TEST_ASSERT_TRUE(esc(in) == std::string("a\\\"b\\\\c"));
}

// C0 control characters: the named ones use short escapes, the rest use \uXXXX.
void test_escapes_control_characters() {
  const char raw[] = {'\n', '\t', '\r', 0x01};
  const std::string in(raw, sizeof(raw));
  TEST_ASSERT_TRUE(esc(in) == std::string("\\n\\t\\r\\u0001"));
}

// 0x7F (DEL) is a control char and must be escaped as \u007f (lowercase hex).
void test_escapes_del() {
  const char raw[] = {0x7F};
  TEST_ASSERT_TRUE(esc(std::string(raw, sizeof(raw))) == std::string("\\u007f"));
}

// Valid UTF-8 multi-byte sequences pass through verbatim; a trailing invalid
// byte becomes the U+FFFD replacement escape "�".
void test_passes_valid_utf8_and_replaces_invalid() {
  const unsigned char raw[] = {0xC3, 0xA9, 0xFF};  // "é" then a stray byte
  const std::string in(reinterpret_cast<const char*>(raw), sizeof(raw));
  const std::string expected = std::string("\xC3\xA9") + "\\ufffd";
  TEST_ASSERT_TRUE(esc(in) == expected);
}

// A plain ASCII SSID is returned unchanged.
void test_plain_ascii_unchanged() {
  TEST_ASSERT_TRUE(esc("HomeNetwork") == std::string("HomeNetwork"));
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_escapes_quote_and_backslash);
  RUN_TEST(test_escapes_control_characters);
  RUN_TEST(test_escapes_del);
  RUN_TEST(test_passes_valid_utf8_and_replaces_invalid);
  RUN_TEST(test_plain_ascii_unchanged);
  return UNITY_END();
}
