#include "Buffer.h"
#include "PcapHeader.h"
#include "lang_var.h"
#include "JsonSerial.h"
#include "Crc32Stream.h"

Buffer::Buffer(){
  bufA = (uint8_t*)malloc(BUF_SIZE);
  bufB = (uint8_t*)malloc(BUF_SIZE);
}

void Buffer::createFile(const char* name, bool is_pcap, bool is_gpx){
  int i=0;
  String prefix = directory ? String(directory) + "/" : "/";
  if (is_pcap) {
    do{
      fileName = prefix+String(name)+"_"+(String)i+".pcap";
      i++;
    } while(fs->exists(fileName));
  }
  else if ((!is_pcap) && (!is_gpx)) {
    do{
      fileName = prefix+String(name)+"_"+(String)i+".log";
      i++;
    } while(fs->exists(fileName));
  }
  else {
    do{
      fileName = prefix+String(name)+"_"+(String)i+".gpx";
      i++;
    } while(fs->exists(fileName));
  }

  Serial.println(fileName);
  
  file = fs->open(fileName, FILE_WRITE);
  file.close();
}

void Buffer::open(bool is_pcap){
  bufSizeA = 0;
  bufSizeB = 0;

  bufSizeB = 0;

  writing = true;

  if (is_pcap) {
    uint8_t header[marauder::kPcapGlobalHeaderSize];
    marauder::makePcapGlobalHeader(SNAP_LEN, header);
    write(header, sizeof(header));
  }
}

String Buffer::getFileName() {
  return this->fileName;
}

void Buffer::setDirectory(const char* path) {
  directory = path;
}

void Buffer::openFile(const char* file_name, fs::FS* fs, bool serial, bool is_pcap, bool is_gpx) {
  bool save_pcap = settings_obj.loadSetting<bool>("SavePCAP");
  if (!save_pcap) {
    this->fs = NULL;
    this->serial = false;
    writing = false;
    return;
  }
  this->fs = fs;
  this->serial = serial;

  // Select the binary (proto >= 2) serial sink when a JSON host is driving the
  // link; otherwise fall back to the legacy [BUF/BEGIN]/[BUF/CLOSE] markers.
  this->stream_type = is_pcap ? 0 : (is_gpx ? 2 : 1);
  this->json_capture = this->serial && JsonSerial::jsonModeEnabled();
  this->capture_seq = 0;
  this->dropped_since_flush = 0;

  if (this->fs) {
    createFile(file_name, is_pcap, is_gpx);
  }
  if (this->fs || this->serial) {
    open(is_pcap);
  } else {
    writing = false;
  }
}

void Buffer::pcapOpen(const char* file_name, fs::FS* fs, bool serial) {
  openFile(file_name, fs, serial, true);
}

void Buffer::logOpen(const char* file_name, fs::FS* fs, bool serial) {
  openFile(file_name, fs, serial, false);
}

void Buffer::gpxOpen(const char* file_name, fs::FS* fs, bool serial) {
  openFile(file_name, fs, serial, false, true);
}

void Buffer::add(const uint8_t* buf, uint32_t len, bool is_pcap){
  constexpr uint32_t pcap_record_header_len = 16;
  const uint32_t record_header_len = is_pcap ? pcap_record_header_len : 0;
  if (!writing || !buf || len > BUF_SIZE || record_header_len + len > BUF_SIZE) return;

  portENTER_CRITICAL(&bufferMux);

  if (saving) {
    portEXIT_CRITICAL(&bufferMux);
    return;
  }

  // buffer is full -> drop packet
  if((useA && bufSizeA + record_header_len + len > BUF_SIZE && bufSizeB > 0) ||
     (!useA && bufSizeB + record_header_len + len > BUF_SIZE && bufSizeA > 0)){
    //Serial.print(";");
    if (json_capture) dropped_since_flush++;
    portEXIT_CRITICAL(&bufferMux);
    return;
  }
  
  if(useA && bufSizeA + record_header_len + len > BUF_SIZE && bufSizeB == 0){
    useA = false;
    //Serial.println("\nswitched to buffer B");
  }
  else if(!useA && bufSizeB + record_header_len + len > BUF_SIZE && bufSizeA == 0){
    useA = true;
    //Serial.println("\nswitched to buffer A");
  }

  uint32_t microSeconds = micros(); // e.g. 45200400 => 45s 200ms 400us
  uint32_t seconds = (microSeconds/1000)/1000; // e.g. 45200400/1000/1000 = 45200 / 1000 = 45s

  microSeconds -= seconds*1000*1000; // e.g. 45200400 - 45*1000*1000 = 45200400 - 45000000 = 400us (because we only need the offset)
  
  if (is_pcap) {
    uint8_t header[pcap_record_header_len];
    const uint32_t values[] = {seconds, microSeconds, len, len};
    for (size_t i = 0; i < 4; i++) {
      header[i * 4] = values[i];
      header[i * 4 + 1] = values[i] >> 8;
      header[i * 4 + 2] = values[i] >> 16;
      header[i * 4 + 3] = values[i] >> 24;
    }
    writeUnlocked(header, sizeof(header));
  }
  
  writeUnlocked(buf, len); // packet payload
  portEXIT_CRITICAL(&bufferMux);
}

void Buffer::append(wifi_promiscuous_pkt_t *packet, int len) {
  bool save_packet = settings_obj.loadSetting<bool>(text_table4[7]);
  if (save_packet) {
    add(packet->payload, len, true);
  }
}

void Buffer::append(String log) {
  bool save_packet = settings_obj.loadSetting<bool>(text_table4[7]);
  if (save_packet) {
    add((const uint8_t*)log.c_str(), log.length(), false);
  }
}

void Buffer::write(int32_t n){
  uint8_t buf[4];
  buf[0] = n;
  buf[1] = n >> 8;
  buf[2] = n >> 16;
  buf[3] = n >> 24;
  write(buf,4);
}

void Buffer::write(uint32_t n){
  uint8_t buf[4];
  buf[0] = n;
  buf[1] = n >> 8;
  buf[2] = n >> 16;
  buf[3] = n >> 24;
  write(buf,4);
}

void Buffer::write(uint16_t n){
  uint8_t buf[2];
  buf[0] = n;
  buf[1] = n >> 8;
  write(buf,2);
}

void Buffer::write(const uint8_t* buf, uint32_t len){
  if(!writing || !buf || len > BUF_SIZE) return;
  portENTER_CRITICAL(&bufferMux);
  if (!saving) writeUnlocked(buf, len);
  portEXIT_CRITICAL(&bufferMux);
}

bool Buffer::writeUnlocked(const uint8_t* buf, uint32_t len){
  if(useA){
    if (len > BUF_SIZE - bufSizeA) return false;
    memcpy(&bufA[bufSizeA], buf, len);
    bufSizeA += len;
  }else{
    if (len > BUF_SIZE - bufSizeB) return false;
    memcpy(&bufB[bufSizeB], buf, len);
    bufSizeB += len;
  }
  return true;
}

void Buffer::saveFs(){
  file = fs->open(fileName, FILE_APPEND);
  if (!file) {
    Serial.println(text02+fileName+"'");
    return;
  }

  if(useA){
    if(bufSizeB > 0){
      file.write(bufB, bufSizeB);
    }
    if(bufSizeA > 0){
      file.write(bufA, bufSizeA);
    }
  } else {
    if(bufSizeA > 0){
      file.write(bufA, bufSizeA);
    }
    if(bufSizeB > 0){
      file.write(bufB, bufSizeB);
    }
  }

  file.close();
}

void Buffer::saveSerial() {
  // Saves to main console UART, user-facing app will ignore these markers
  // Uses / and ] in markers as they are illegal characters for SSIDs
  const char* mark_begin = "[BUF/BEGIN]";
  const size_t mark_begin_len = strlen(mark_begin);
  const char* mark_close = "[BUF/CLOSE]";
  const size_t mark_close_len = strlen(mark_close);

  // Additional buffer and memcpy's so that a single Serial.write() is called
  // This is necessary so that other console output isn't mixed into buffer stream
  uint8_t* buf = (uint8_t*)malloc(mark_begin_len + bufSizeA + bufSizeB + mark_close_len);
  uint8_t* it = buf;
  memcpy(it, mark_begin, mark_begin_len);
  it += mark_begin_len;

  if(useA){
    if(bufSizeB > 0){
      memcpy(it, bufB, bufSizeB);
      it += bufSizeB;
    }
    if(bufSizeA > 0){
      memcpy(it, bufA, bufSizeA);
      it += bufSizeA;
    }
  } else {
    if(bufSizeA > 0){
      memcpy(it, bufA, bufSizeA);
      it += bufSizeA;
    }
    if(bufSizeB > 0){
      memcpy(it, bufB, bufSizeB);
      it += bufSizeB;
    }
  }

  memcpy(it, mark_close, mark_close_len);
  it += mark_close_len;
  Serial.write(buf, it - buf);
  free(buf);
}

void Buffer::saveSerialBinary() {
  // Frame the flushed buffer for the companion app's SerialDemux:
  //   SYNC(FE ED FA CE) | seq(LE32) | type(u8) | len(LE32) | payload | crc32(LE32)
  // The CRC-32 covers the 9-byte header (seq+type+len) followed by the payload
  // (see Crc32Stream.h / Crc32.kt). The whole frame is assembled and written
  // with a single Serial.write() so no other console output can interleave
  // inside it. 0xFE never appears in the firmware's text/JSON output, so the
  // SYNC prefix unambiguously marks a binary frame to the host.
  const uint32_t total = bufSizeA + bufSizeB;
  if (total == 0) return;

  const uint32_t seq = this->capture_seq++;
  const size_t frame_len = 4 /*SYNC*/ + 9 /*header*/ + (size_t)total + 4 /*crc*/;
  uint8_t* frame = (uint8_t*)malloc(frame_len);
  if (!frame) {
    // Could not frame this flush: count the whole chunk as dropped so the host
    // is told there is a gap on the next successful frame.
    this->dropped_since_flush += total;
    return;
  }

  frame[0] = 0xFE; frame[1] = 0xED; frame[2] = 0xFA; frame[3] = 0xCE;

  uint8_t* h = frame + 4;  // header: seq (LE32), type (u8), len (LE32)
  h[0] = (uint8_t)(seq);
  h[1] = (uint8_t)(seq >> 8);
  h[2] = (uint8_t)(seq >> 16);
  h[3] = (uint8_t)(seq >> 24);
  h[4] = this->stream_type;
  h[5] = (uint8_t)(total);
  h[6] = (uint8_t)(total >> 8);
  h[7] = (uint8_t)(total >> 16);
  h[8] = (uint8_t)(total >> 24);

  // Payload in the same A/B ordering saveFs()/saveSerial() use.
  uint8_t* p = frame + 13;
  if(useA){
    if(bufSizeB > 0){ memcpy(p, bufB, bufSizeB); p += bufSizeB; }
    if(bufSizeA > 0){ memcpy(p, bufA, bufSizeA); p += bufSizeA; }
  } else {
    if(bufSizeA > 0){ memcpy(p, bufA, bufSizeA); p += bufSizeA; }
    if(bufSizeB > 0){ memcpy(p, bufB, bufSizeB); p += bufSizeB; }
  }

  const uint32_t crc = marauder::captureFrameCrc32(frame + 4, 9, frame + 13, total);
  uint8_t* t = frame + 13 + total;
  t[0] = (uint8_t)(crc);
  t[1] = (uint8_t)(crc >> 8);
  t[2] = (uint8_t)(crc >> 16);
  t[3] = (uint8_t)(crc >> 24);

  Serial.write(frame, frame_len);
  free(frame);

  // Tell the host about any ring overruns since the previous frame. Emitted as
  // a text "@J drop" line (safe: it follows the completed binary frame).
  if (this->dropped_since_flush > 0) {
    JsonSerial::emitDrop(this->dropped_since_flush);
    this->dropped_since_flush = 0;
  }
}

void Buffer::save() {
  portENTER_CRITICAL(&bufferMux);
  saving = true;

  if((bufSizeA + bufSizeB) == 0){
    saving = false;
    portEXIT_CRITICAL(&bufferMux);
    return;
  }
  portEXIT_CRITICAL(&bufferMux);

  if(this->fs) saveFs();
  if(this->serial) {
    if(this->json_capture) saveSerialBinary();
    else saveSerial();
  }

  portENTER_CRITICAL(&bufferMux);
  bufSizeA = 0;
  bufSizeB = 0;
  saving = false;
  portEXIT_CRITICAL(&bufferMux);
}
