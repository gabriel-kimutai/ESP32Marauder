#pragma once

#ifndef Buffer_h
#define Buffer_h

#include "Arduino.h"
#include "FS.h"
#include "settings.h"
#include "esp_wifi_types.h"
#include "configs.h"

//#define BUF_SIZE 3 * 1024 // Had to reduce buffer size to save RAM. GG @spacehuhn
//#define SNAP_LEN 2324 // max len of each recieved packet

//extern bool useSD;

extern Settings settings_obj;

class Buffer {
  public:
    Buffer();
    void pcapOpen(const char* file_name, fs::FS* fs, bool serial);
    void logOpen(const char* file_name, fs::FS* fs, bool serial);
    void gpxOpen(const char* file_name, fs::FS* fs, bool serial);
    void append(wifi_promiscuous_pkt_t *packet, int len);
    void append(String log);
    void save();
    String getFileName();
    void setDirectory(const char* path);
  private:
    void createFile(const char* name, bool is_pcap, bool is_gpx = false);
    void open(bool is_pcap);
    void openFile(const char* file_name, fs::FS* fs, bool serial, bool is_pcap, bool is_gpx = false);
    void add(const uint8_t* buf, uint32_t len, bool is_pcap);
    void write(int32_t n);
    void write(uint32_t n);
    void write(uint16_t n);
    void write(const uint8_t* buf, uint32_t len);
    bool writeUnlocked(const uint8_t* buf, uint32_t len);
    void saveFs();
    void saveSerial();
    // proto >= 2 binary capture sink: frame the flushed buffer as
    //   SYNC(FE ED FA CE) | seq(LE32) | type(u8) | len(LE32) | payload | crc32(LE32)
    // for the companion app's SerialDemux. Used instead of saveSerial() while a
    // JSON host is driving the link (json_capture).
    void saveSerialBinary();

    uint8_t* bufA;
    uint8_t* bufB;

    uint32_t bufSizeA = 0;
    uint32_t bufSizeB = 0;

    bool writing = false; // acceppting writes to buffer
    bool useA = true; // writing to bufA or bufB
    bool saving = false; // currently saving onto the SD card
    portMUX_TYPE bufferMux = portMUX_INITIALIZER_UNLOCKED;

    String fileName = "/0.pcap";
    const char* directory = NULL;
    File file;
    fs::FS* fs;
    bool serial;

    // Binary capture streaming state (proto >= 2). json_capture selects the
    // framed serial sink; stream_type is 0=pcap, 1=log, 2=gpx; capture_seq is
    // the per-session frame counter; dropped_since_flush counts ring overruns
    // reported to the host via an "@J drop" line on the next flush.
    bool json_capture = false;
    uint8_t stream_type = 0;
    uint32_t capture_seq = 0;
    uint32_t dropped_since_flush = 0;
};

#endif
