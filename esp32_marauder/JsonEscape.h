#pragma once
#ifndef JsonEscape_h
#define JsonEscape_h

// ----------------------------------------------------------------------------
//  JsonEscape - escape an arbitrary byte string for safe inclusion inside a
//  JSON string literal, UTF-8 aware.
//
//  802.11 SSIDs (and Evil Portal form input) are arbitrary byte strings, so the
//  output must always be valid JSON/UTF-8 regardless of the input bytes:
//    * ", \, and the C0 control characters (plus 0x7F) are escaped;
//    * valid UTF-8 multi-byte sequences are passed through verbatim;
//    * any byte that is not part of a well-formed UTF-8 sequence (including
//      overlong encodings, UTF-16 surrogates and code points > U+10FFFF) is
//      replaced with the U+FFFD replacement character ("�").
//
//  Header-only and dependency-free (std::string only) so the native Unity test
//  suite exercises the exact same routine that formats device output.
// ----------------------------------------------------------------------------

#include <cstdio>
#include <stddef.h>
#include <stdint.h>
#include <string>

namespace marauder {

inline void jsonEscapeAppend(std::string& out, const uint8_t* in, size_t n) {
  for (size_t i = 0; i < n;) {
    uint8_t c = in[i];

    if (c < 0x80) {  // ASCII
      switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
          if (c < 0x20 || c == 0x7F) {
            char buf[7];
            snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
            out += buf;
          } else {
            out += (char)c;
          }
      }
      i++;
      continue;
    }

    // Multi-byte UTF-8: validate the length, the continuation bytes AND the
    // decoded code point before passing the bytes through unchanged.
    int seqLen = 0;
    if ((c & 0xE0) == 0xC0) seqLen = 2;
    else if ((c & 0xF0) == 0xE0) seqLen = 3;
    else if ((c & 0xF8) == 0xF0) seqLen = 4;

    bool valid = (seqLen >= 2) && (i + (size_t)seqLen <= n);
    uint32_t cp = 0;
    if (valid) {
      cp = (uint32_t)(c & (0xFF >> (seqLen + 1)));
      for (int k = 1; k < seqLen; k++) {
        uint8_t cc = in[i + k];
        if ((cc & 0xC0) != 0x80) { valid = false; break; }
        cp = (cp << 6) | (uint32_t)(cc & 0x3F);
      }
    }
    if (valid) {
      static const uint32_t minCp[5] = {0, 0, 0x80, 0x800, 0x10000};
      if (cp < minCp[seqLen] || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF)
        valid = false;
    }

    if (valid) {
      for (int k = 0; k < seqLen; k++) out += (char)in[i + k];
      i += (size_t)seqLen;
    } else {
      out += "\\ufffd";  // invalid byte -> U+FFFD replacement character
      i++;
    }
  }
}

inline std::string jsonEscape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  jsonEscapeAppend(out, (const uint8_t*)in.data(), in.size());
  return out;
}

}  // namespace marauder

#endif
