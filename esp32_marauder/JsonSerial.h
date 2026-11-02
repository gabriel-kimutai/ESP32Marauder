#pragma once
#ifndef JsonSerial_h
#define JsonSerial_h

// ----------------------------------------------------------------------------
//  JsonSerial - machine-readable (JSON) command set for the serial CLI
//
//  Adds a small set of structured commands so a companion program driving the
//  USB serial port can parse device data reliably instead of scraping the
//  human-formatted CLI text. Every line of machine-readable output is prefixed
//  with "@J " so a host can cleanly separate it from the regular human-readable
//  CLI output the firmware already produces. These commands DO NOT touch the
//  scanning internals - they only read the data structures the firmware already
//  maintains (access_points, stations, ssids, ...).
//
//  The exact field names/types of every emitted object are the contract defined
//  by the companion app's LineParser.kt / DeviceMessage.kt. Do not rename a
//  field without changing the parser in lock-step.
//
//  Commands (all handled in JsonSerial::handle):
//    jsoninfo               -> one {"t":"info", ...} handshake line
//    jsonstatus             -> one {"t":"status", ...} line (poll friendly)
//    jsonmode <0|1>         -> toggle continuous @J streaming + reply {"t":"jsonmode"}
//    jsonlist <a|s|c|i|p|t> -> one row object per entry + a closing {"t":"end"}
//    jsonbaud <rate>        -> confirm {"t":"baud"} at the OLD rate, then switch
// ----------------------------------------------------------------------------

#include "configs.h"
#include <Arduino.h>
#include <LinkedList.h>

// JSON protocol version reported by jsoninfo. proto >= 2 adds length-prefixed
// binary capture streaming, jsonbaud, the Evil Portal serial upload and the
// analyzer streaming. Overridable from configs.h.
#ifndef MARAUDER_JSON_PROTO
  #define MARAUDER_JSON_PROTO 2
#endif

// Prefix that tags every machine-readable line.
#define JSON_LINE_PREFIX "@J "

// Command tokens
const char PROGMEM JSON_INFO_CMD[]   = "jsoninfo";
const char PROGMEM JSON_LIST_CMD[]   = "jsonlist";
const char PROGMEM JSON_STATUS_CMD[] = "jsonstatus";
const char PROGMEM JSON_MODE_CMD[]   = "jsonmode";
const char PROGMEM JSON_BAUD_CMD[]   = "jsonbaud";

namespace JsonSerial {
  // Returns true if cmd_args[0] was a JSON command (and it was handled).
  // Returns false otherwise so the normal CLI dispatch can continue.
  bool handle(LinkedList<String>* cmd_args);

  // True once a host has requested JSON mode (via `jsoninfo` or `jsonmode 1`).
  // Continuous streaming (analyzer samples, capture drops) and binary capture
  // framing are all gated on this so a plain serial monitor is never flooded
  // with "@J" lines or raw binary.
  bool jsonModeEnabled();

  // Emit the capabilities array (including the surrounding [ ]). Shared by the
  // jsoninfo handshake and the legacy `protocolinfo` handshake so both report
  // the same feature set.
  void printCapsArray();

  // Analyzer streaming (gated by jsonModeEnabled). The host redraws the charts
  // itself from the streamed values.
  //   emitAnalyzerSample: one new rolling-graph sample per refresh (Channel
  //     Analyzer / BT Analyzer). mode = scan-mode constant; ch = current WiFi
  //     channel, or -1 when not channel-meaningful (BT analyzer); value = sample.
  void emitAnalyzerSample(uint8_t mode, int ch, int16_t value);

  //   emitChannelActivity: the currently displayed page of the Channel Activity
  //     bar chart, as parallel arrays of real channel numbers (ch[]) and their
  //     counts (v[]), plus the 1-based page index.
  void emitChannelActivity(const int* channels, const uint8_t* values, int count, int page);

  // emitCred: one captured Evil Portal submission ({"t":"cred","u":..,"p":..}).
  // Both fields are JSON/UTF-8 escaped. Gated by jsonModeEnabled().
  void emitCred(const String& user, const String& pass);

  // emitDrop: report the number of capture chunks the device dropped (ring
  // buffer full) since the last flush. {"t":"drop","n":<count>}. Gated by
  // jsonModeEnabled().
  void emitDrop(unsigned long n);
}

#endif
