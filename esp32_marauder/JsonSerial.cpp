#include "JsonSerial.h"

#include <string>

#include "WiFiScan.h"
#include "EvilPortal.h"
#include "utils.h"
#include "JsonEscape.h"

// Globals defined in WiFiScan.cpp / esp32_marauder.ino (mirrors CommandLine.h)
extern LinkedList<AccessPoint>* access_points;
extern LinkedList<Station>* stations;
extern LinkedList<ssid>* ssids;
extern LinkedList<IPAddress>* ipList;
extern LinkedList<ProbeReqSsid>* probe_req_ssids;
extern LinkedList<AirTag>* airtags;
extern WiFiScan wifi_scan_obj;
extern const String PROGMEM version_number;

// When false, continuous streaming (analyzer samples, capture-drop reports) and
// binary capture framing are suppressed so a plain serial monitor (no JSON
// host) is never flooded with "@J" lines or raw binary. Enabled by the
// `jsoninfo` handshake or an explicit `jsonmode 1`.
static bool g_jsonMode = false;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// Escape an Arduino String for safe inclusion inside a JSON string literal.
// Delegates to the header-only, UTF-8-aware routine shared with the native
// tests (JsonEscape.h).
static String jsonEscape(const String& in) {
  std::string out =
      marauder::jsonEscape(std::string(in.c_str(), in.length()));
  return String(out.c_str());
}

// Emit  "key":true,  (or false). Pass comma=false to omit the trailing comma.
static inline void boolField(const __FlashStringHelper* key, bool v, bool comma = true) {
  Serial.print(key);
  Serial.print(v ? F("true") : F("false"));
  if (comma) Serial.print(F(","));
}

// ---------------------------------------------------------------------------
// Capabilities advertisement (shared by jsoninfo + protocolinfo)
// ---------------------------------------------------------------------------
void JsonSerial::printCapsArray() {
  // WiFi is present on every supported board, so it is always emitted first;
  // every other capability is conditionally appended with a leading comma.
  Serial.print(F("[\"wifi\""));
  // proto >= 2, board-independent host-side features.
  Serial.print(F(",\"capstream\""));         // length-prefixed binary capture
  Serial.print(F(",\"evilportal-upload\""));  // portal recv/set serial upload
  Serial.print(F(",\"analyzer\""));           // asample / chan streaming
  #ifdef HAS_GPS
    Serial.print(F(",\"gps\""));
    Serial.print(F(",\"wardrive-stream\""));
  #endif
  #ifdef HAS_BT
    Serial.print(F(",\"bt\""));
  #endif
  #ifdef HAS_SD
    Serial.print(F(",\"sd\""));
  #endif
  #ifdef HAS_SCREEN
    Serial.print(F(",\"screen\""));
  #endif
  Serial.print(F("]"));
}

// ---------------------------------------------------------------------------
// jsoninfo - handshake / capability advertisement
// ---------------------------------------------------------------------------
static void printInfo() {
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"info\",\"fw\":\""));
  Serial.print(version_number);
  Serial.print(F("\",\"proto\":"));
  Serial.print(MARAUDER_JSON_PROTO);
  Serial.print(F(",\"board\":\""));
  Serial.print(F(HARDWARE_NAME));
  Serial.print(F("\",\"caps\":"));
  JsonSerial::printCapsArray();
  Serial.println(F("}"));
}

// ---------------------------------------------------------------------------
// jsonstatus - lightweight, poll friendly device state
// ---------------------------------------------------------------------------
static void printStatus() {
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"status\",\"mode\":"));
  Serial.print(wifi_scan_obj.currentScanMode);
  Serial.print(F(",")); boolField(F("\"running\":"), wifi_scan_obj.scanning());
  Serial.print(F("\"free\":"));
  Serial.print(ESP.getFreeHeap());
  Serial.print(F(",\"aps\":"));
  Serial.print(access_points ? access_points->size() : 0);
  Serial.print(F(",\"stas\":"));
  Serial.print(stations ? stations->size() : 0);
  Serial.print(F(",\"ssids\":"));
  Serial.print(ssids ? ssids->size() : 0);
  Serial.print(F(",\"ips\":"));
  Serial.print(ipList ? ipList->size() : 0);
  Serial.print(F(",\"probes\":"));
  Serial.print(probe_req_ssids ? probe_req_ssids->size() : 0);
  Serial.print(F(",\"airtags\":"));
  Serial.print(airtags ? airtags->size() : 0);
  Serial.println(F("}"));
}

// ---------------------------------------------------------------------------
// jsonlist emitters. Each returns the number of objects it actually emitted so
// the closing {"t":"end"} "n" always matches the streamed rows.
// ---------------------------------------------------------------------------
static int listAps() {
  int n = access_points ? access_points->size() : 0;
  for (int i = 0; i < n; i++) {
    AccessPoint ap = access_points->get(i);
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"ap\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"ch\":"));   Serial.print(ap.channel);
    Serial.print(F(",\"rssi\":")); Serial.print(ap.rssi);
    Serial.print(F(",")); boolField(F("\"sel\":"), ap.selected);
    Serial.print(F("\"pkts\":"));  Serial.print(ap.packets);
    Serial.print(F(",\"sec\":"));  Serial.print(ap.sec);
    Serial.print(F(",")); boolField(F("\"wps\":"), ap.wps);
    Serial.print(F("\"nsta\":"));  Serial.print(ap.stations ? ap.stations->size() : 0);
    Serial.print(F(",\"bssid\":\"")); Serial.print(macToString(ap.bssid));
    Serial.print(F("\",\"essid\":\"")); Serial.print(jsonEscape(ap.essid));
    Serial.println(F("\"}"));
  }
  return n;
}

static int listStations() {
  if (!access_points || !stations) return 0;
  int emitted = 0;
  for (int x = 0; x < access_points->size(); x++) {
    AccessPoint ap = access_points->get(x);
    if (!ap.stations) continue;
    for (int j = 0; j < ap.stations->size(); j++) {
      uint16_t idx = ap.stations->get(j);
      Station st = stations->get(idx);
      Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"sta\",\"ap\":"));
      Serial.print(x);
      Serial.print(F(",\"i\":"));   Serial.print(idx);
      Serial.print(F(",")); boolField(F("\"sel\":"), st.selected);
      Serial.print(F("\"pkts\":")); Serial.print(st.packets);
      Serial.print(F(",\"mac\":\"")); Serial.print(macToString(st.mac));
      Serial.println(F("\"}"));
      emitted++;
    }
  }
  return emitted;
}

static int listSsids() {
  int n = ssids ? ssids->size() : 0;
  for (int i = 0; i < n; i++) {
    ssid s = ssids->get(i);
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"ssid\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"ch\":")); Serial.print(s.channel);
    Serial.print(F(",")); boolField(F("\"sel\":"), s.selected);
    Serial.print(F("\"essid\":\"")); Serial.print(jsonEscape(s.essid));
    Serial.println(F("\"}"));
  }
  return n;
}

static int listIps() {
  int n = ipList ? ipList->size() : 0;
  for (int i = 0; i < n; i++) {
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"ip\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"ip\":\""));
    Serial.print(ipList->get(i).toString());
    Serial.println(F("\"}"));
  }
  return n;
}

static int listProbes() {
  int n = probe_req_ssids ? probe_req_ssids->size() : 0;
  for (int i = 0; i < n; i++) {
    ProbeReqSsid p = probe_req_ssids->get(i);
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"probe\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"req\":")); Serial.print(p.requests);
    Serial.print(F(",")); boolField(F("\"sel\":"), p.selected);
    Serial.print(F("\"essid\":\"")); Serial.print(jsonEscape(p.essid));
    Serial.println(F("\"}"));
  }
  return n;
}

static int listAirtags() {
  int n = airtags ? airtags->size() : 0;
  for (int i = 0; i < n; i++) {
    AirTag a = airtags->get(i);
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"airtag\",\"i\":"));
    Serial.print(i);
    Serial.print(F(",\"rssi\":")); Serial.print(a.rssi);
    Serial.print(F(",")); boolField(F("\"sel\":"), a.selected);
    Serial.print(F("\"mac\":\"")); Serial.print(jsonEscape(a.mac));
    Serial.println(F("\"}"));
  }
  return n;
}

static void printList(char which) {
  int count;
  switch (which) {
    case 'a': count = listAps();      break;
    case 's': count = listSsids();    break;
    case 'c': count = listStations(); break;
    case 'i': count = listIps();      break;
    case 'p': count = listProbes();   break;
    case 't': count = listAirtags();  break;
    default:
      // Unknown list type: report an explicit error instead of silently
      // returning the AP list under the wrong label.
      Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"err\",\"cmd\":\"jsonlist\",\"arg\":\""));
      Serial.print(jsonEscape(String(which)));  // escape so `jsonlist \` stays valid JSON
      Serial.println(F("\"}"));
      return;
  }
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"end\",\"list\":\""));
  Serial.print(which);
  Serial.print(F("\",\"n\":"));
  Serial.print(count);
  Serial.println(F("}"));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
bool JsonSerial::jsonModeEnabled() {
  return g_jsonMode;
}

bool JsonSerial::handle(LinkedList<String>* cmd_args) {
  if (!cmd_args || cmd_args->size() == 0) return false;
  String cmd = cmd_args->get(0);

  if (cmd == JSON_INFO_CMD) {
    g_jsonMode = true;  // a host is talking to us -> enable streaming
    printInfo();
    return true;
  }
  if (cmd == JSON_STATUS_CMD) {
    printStatus();
    return true;
  }
  if (cmd == JSON_MODE_CMD) {
    if (cmd_args->size() > 1) {
      String a = cmd_args->get(1);
      g_jsonMode = (a == "1" || a == "on" || a == "true");
    }
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"jsonmode\","));
    boolField(F("\"on\":"), g_jsonMode, false);
    Serial.println(F("}"));
    return true;
  }
  if (cmd == JSON_BAUD_CMD) {
    // Raise (or lower) the serial line rate so a host can drain captured pcap
    // faster than the 115200 default. The confirmation is sent at the OLD rate
    // and flushed BEFORE switching, so the host can read it, then re-open its
    // port at the new rate - no bytes are lost across the change. On native
    // USB-CDC boards updateBaudRate() is a harmless no-op.
    long rate = (cmd_args->size() > 1) ? cmd_args->get(1).toInt() : 0;
    if (rate < 9600) rate = 115200;  // guard against a bogus / missing argument
    Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"baud\",\"rate\":"));
    Serial.print(rate);
    Serial.println(F("}"));
    Serial.flush();  // drain TX at the old rate before switching
    delay(60);
#if !ARDUINO_USB_CDC_ON_BOOT
    Serial.updateBaudRate((uint32_t)rate);
#endif
    return true;
  }
  if (cmd == JSON_LIST_CMD) {
    char which = 'a';
    if (cmd_args->size() > 1) {
      String a = cmd_args->get(1);
      a.replace("-", "");
      a.trim();
      if (a.length() > 0) which = a.charAt(0);
    }
    printList(which);
    return true;
  }
  return false;
}

void JsonSerial::emitAnalyzerSample(uint8_t mode, int ch, int16_t value) {
  if (!g_jsonMode) return;
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"asample\",\"mode\":"));
  Serial.print(mode);
  Serial.print(F(",\"ch\":"));
  Serial.print(ch);
  Serial.print(F(",\"v\":"));
  Serial.print(value);
  Serial.println(F("}"));
}

void JsonSerial::emitChannelActivity(const int* channels, const uint8_t* values, int count, int page) {
  if (!g_jsonMode || !channels || !values || count <= 0) return;
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"chan\",\"page\":"));
  Serial.print(page);
  Serial.print(F(",\"ch\":["));
  for (int i = 0; i < count; i++) {
    if (i) Serial.print(',');
    Serial.print(channels[i]);
  }
  Serial.print(F("],\"v\":["));
  for (int i = 0; i < count; i++) {
    if (i) Serial.print(',');
    Serial.print(values[i]);
  }
  Serial.println(F("]}"));
}

void JsonSerial::emitCred(const String& user, const String& pass) {
  if (!g_jsonMode) return;
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"cred\",\"u\":\""));
  Serial.print(jsonEscape(user));
  Serial.print(F("\",\"p\":\""));
  Serial.print(jsonEscape(pass));
  Serial.println(F("\"}"));
}

void JsonSerial::emitDrop(unsigned long n) {
  if (!g_jsonMode || n == 0) return;
  Serial.print(F(JSON_LINE_PREFIX "{\"t\":\"drop\",\"n\":"));
  Serial.print(n);
  Serial.println(F("}"));
}
