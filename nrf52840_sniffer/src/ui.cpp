#include "shared.h"
#include <bluefruit.h> 

// =============================================================================
//                             EXTERNS
// =============================================================================
extern bool promiscuous_mode;
extern bool use_preset_mode;
extern void run_smart_address_search(); 

// =============================================================================
//                             PRINT HELPERS
// =============================================================================

void print_byte(uint8_t b) {
    if (b < 0x10) Serial.print('0');
    Serial.print(b, HEX);
}

void print_hex(const uint8_t* b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    print_byte(b[i]);
    Serial.print(' ');
  }
  Serial.println();
}

void print_ts() {
  Serial.print('['); Serial.print(millis()); Serial.print(" ms] ");
}

// =============================================================================
//                             UI / MENUS
// =============================================================================

void print_params() {
  Serial.println(F("\n--- Current Settings ---"));
  
  // 1. System State & Sniffer Mode
  Serial.print(F("State: "));
  switch (currentState) {
    case IDLE: Serial.println(F("IDLE")); break;
    case SWEEPING: Serial.println(F("SWEEPING")); break;
    case ANALYZING: Serial.println(F("ANALYZING")); break;
    case LISTENING: Serial.println(F("LISTENING")); break;
  }

  Serial.print(F("Sniffer Mode: "));
  if (promiscuous_mode) {
      Serial.println(F("RAW CAPTURE (SW Validation)"));
      Serial.println(F("   -> HW Address Filter: DISABLED (Trigger on Preamble)"));
      Serial.println(F("   -> HW CRC: DISABLED"));
      Serial.println(F("   -> SW Validation: ENABLED (CRC16 + Bit-Shift + Repair)"));
  } else {
      Serial.println(F("STANDARD (HW Filtering)"));
      Serial.println(F("   -> HW Address Filter: ENABLED"));
  }

  // 2. RF Physical Layer
  Serial.print(F("Locked Channel: ")); Serial.println(best_ch_found);
  Serial.print(F("Data Rate: ")); Serial.println((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2M" : "1M");
  Serial.print(F("Whitening: ")); Serial.println(whitening_enabled ? "ENABLED" : "DISABLED");
  
  // 3. Address / Pipe Config
  Serial.print(F("Addr Logic: ")); Serial.println(use_preset_mode ? "PRESET" : "MANUAL");
  if (use_preset_mode) {
      Serial.print(F("Preset: [")); Serial.print(current_preset_idx); Serial.print(F("] ")); Serial.println(PRESETS[current_preset_idx]->name);
      if (!promiscuous_mode) {
         Serial.print(F("Focus: "));
         if (focused_pipe_idx == -1) Serial.println(F("ALL Pipes"));
         else { Serial.print(F("Pipe ")); Serial.println(focused_pipe_idx); }
      }
  } else {
      Serial.print (F("Manual Prefix/pipe: "));
      if (have_prefix) { Serial.print(F("discovered 0x")); Serial.print(discovered_prefix, HEX); }
      else { Serial.print(F("0xAA (default)")); }
      Serial.println(F(" on pipe0"));
      
      Serial.print(F("Discovered base bytes (LSB->MSB): "));
      if (discovered_count==0) Serial.println(F("(none)"));
      else {
        for(int i=0;i<discovered_count;i++){ Serial.print("0x"); Serial.print(discovered_base[i], HEX); Serial.print(i<discovered_count-1?" ":""); }
        Serial.println();
      }
  }

  // 4. Packet Configuration
  Serial.print(F("BALEN: ")); Serial.println(BALEN);
  Serial.print(F("LFLEN: ")); Serial.println(LFLEN);
  Serial.print(F("S1LEN: ")); Serial.println(S1LEN);
  Serial.print(F("STATLEN: ")); Serial.println(STATLEN);
  Serial.print(F("Header parse: ")); Serial.println(header_parse_enabled ? "ENABLED" : "DISABLED");
  Serial.print(F("Payload Endian: ")); Serial.println(payload_endian_little ? "Little (nRF)" : "Big (BLE)");
  Serial.print(F("RSSI print threshold: ")); Serial.print(PRINT_RSSI_THRESH); Serial.println(F(" dBm"));

  // 5. CRC (Display logic based on mode)
  if (promiscuous_mode) {
      Serial.println(F("CRC: Handled by Software (Force enabled for validation)"));
  } else {
      Serial.print(F("CRC Length: ")); 
      if (current_crc_len == 0) Serial.println(F("DISABLED"));
      else if (current_crc_len == 1) Serial.println(F("1 Byte"));
      else if (current_crc_len == 2) Serial.println(F("2 Bytes"));
      
      Serial.print (F("CRC Skip Address: ")); Serial.println(crc_skip_addr ? "Skip (Payload Only)" : "Include (Addr + Payload)");
      Serial.print (F("CRC Profile: "));
      switch (crc_param_profile) {
        case 0: Serial.println(F("0: Default (Poly:0x1021, Init:0xFFFF)")); break;
        case 1: Serial.println(F("1: Kermit  (Poly:0x1021, Init:0x0000)")); break;
        case 2: Serial.println(F("2: Modbus  (Poly:0x8005, Init:0xFFFF)")); break;
        case 3: Serial.println(F("3: ARC     (Poly:0x8005, Init:0x0000)")); break;
      }
  }

  // 6. Tools
  Serial.print(F("Manual Bit Shift: ")); Serial.println(bit_shift_amount);
  Serial.print(F("Output Format: ")); Serial.println(clean_output_mode ? "CLEAN (Payload Only)" : "VERBOSE");
  Serial.print(F("Recorded packets: ")); Serial.print(recorded_packet_count);
  Serial.print(F(" / ")); Serial.println(MAX_RECORDED_PACKETS);
  Serial.println(F("------------------------\n"));
}

void print_help() {
  Serial.println(F("\nKeys:"));
  Serial.println(F("  h   : help"));
  Serial.println(F("  P   : print current parameter settings"));
  Serial.println(F("  S   : run a single sweep"));
  Serial.println(F("  T   : set exact RSSI threshold in dBm (e.g., -55) then Enter"));
  Serial.println(F("  [   : raise RSSI threshold by +5 dB"));
  Serial.println(F("  ]   : lower RSSI threshold by -5 dB"));

  Serial.println(F("  ------------------- Mode Selection --------------------"));
  Serial.println(F("  A   : AUTO SMART SCAN (Runs Raw Capture Mode to find addrs)"));
  Serial.println(F("  a   : Listen ALL Pipes (Forces Standard HW Mode)"));
  Serial.println(F("  n   : Cycle Presets (Forces Standard HW Mode)"));
  Serial.println(F("  M   : Set Manual Address (Forces Standard HW Mode)"));

  Serial.println(F("  ----------------------- Pipes -------------------------"));
  Serial.println(F("  0-7 : focus on specific pipe # (Standard HW Mode only)"));

  Serial.println(F("  ------------------- Record / Fire ---------------------"));
  Serial.println(F("  R   : toggle packet recording (LISTENING only)"));
  Serial.println(F("  f   : fire (transmit) recorded packets"));

  Serial.println(F("  ------------------ Sniffer Config ---------------------"));
  Serial.println(F("  W   : toggle whitening"));
  Serial.println(F("  D   : toggle data rate (1M/2M)"));
  Serial.println(F("  b   : cycle BALEN (1..4)"));
  Serial.println(F("  l   : cycle LFLEN (0..8)"));
  Serial.println(F("  s   : cycle S1LEN (0..7)"));
  Serial.println(F("  t   : cycle STATLEN (0/6/8/16/24/32/64)"));
  Serial.println(F("  K   : set exact STATLEN (0-255) then Enter"));
  Serial.println(F("  C   : cycle CRC (Off/1B/2B) (Standard Mode only)"));
  Serial.println(F("  V   : cycle CRC Profile (Poly/Init)"));
  Serial.println(F("  e   : cycle Payload Endianness (Little/Big)"));
  Serial.println(F("  i   : cycle CRC Skip Address (Include/Skip)"));
  Serial.println(F("  L   : cycle Preamble Length (8/16/32/Long)"));
  Serial.println(F("  p   : toggle header parsing (LEN/S1)"));
  Serial.println(F("  r   : reapply radio with current params"));
  Serial.println(F("  < / > : bit-shift printed payload left/right (-7 to +7)"));
  Serial.println(F("  + / - : channel up/down"));
  Serial.println(F("  c   : enter channel number + Enter"));
  Serial.println(F("  o   : toggle output mode (Verbose/Clean)"));

  Serial.print  (F("\nRSSI print gate: "));
  Serial.print(PRINT_RSSI_THRESH);
  Serial.println(F(" dBm"));
}

// =============================================================================
//                             INPUT PARSING
// =============================================================================

String chan_entry;
String thresh_entry;
String addr_entry;
String statlen_entry;
bool entering_thresh = false;
bool entering_address = false;
bool entering_statlen = false;
bool entering_channel = false;

void serial_commands() {
  while (Serial.available()) {
    char c = Serial.read();

    // --- ENTER KEY HANDLING ---
    if (c == '\r' || c == '\n') {
      if (entering_channel && chan_entry.length()) { 
        int ch = chan_entry.toInt(); 
        chan_entry = "";
        if (ch >= MIN_CH && ch <= MAX_CH) {
          best_ch_found = (uint8_t)ch;
          if (currentState == IDLE) { 
             Serial.println(">>> IDLE exit: Manual channel set.");
             configure_radio_for_state(LISTENING); currentState = LISTENING;
          } else {
             set_channel(best_ch_found);
          }
          Serial.print("Channel set to "); Serial.println(best_ch_found);
        } else {
           Serial.println("Channel out of range.");
        }
        entering_channel = false;
      }
      
      if (entering_thresh && thresh_entry.length()) {
        int val = thresh_entry.toInt();
        if (val < -100) val = -100; 
        if (val > -20) val = -20;
        PRINT_RSSI_THRESH = (int8_t)val;
        Serial.print("RSSI threshold set to "); Serial.print(PRINT_RSSI_THRESH); Serial.println(" dBm");
        entering_thresh = false; thresh_entry = "";
      }
      
      if (entering_address && addr_entry.length()) {
        set_manual_address(addr_entry);
        entering_address = false; addr_entry = "";
      }
      
      if (entering_statlen && statlen_entry.length()) {
        int len = statlen_entry.toInt();
        if (len < 0) len = 0; 
        if (len > 255) len = 255;
        STATLEN = (uint8_t)len; apply_pcnf0_pcnf1();
        Serial.print("STATLEN manually set to "); Serial.println(STATLEN);
        entering_statlen = false; statlen_entry = "";
      }
      continue;
    }

    // --- INPUT CAPTURE ---
    if (entering_channel) {
      if (isDigit(c)) { chan_entry += c; Serial.print(c); continue; }
    }
    
    if (entering_thresh && (isDigit(c) || c=='-')) {
      thresh_entry += c; Serial.print(c); continue;
    } else if (entering_thresh) { entering_thresh = false; thresh_entry = ""; }

    if (entering_address && (isDigit(c) || (c>='a' && c<='f') || (c>='A' && c<='F') || c==' ')) {
      addr_entry += c; Serial.print(c); continue;
    } else if (entering_address) { entering_address = false; addr_entry = ""; }

    if (entering_statlen && isDigit(c)) {
      statlen_entry += c; Serial.print(c); continue;
    } else if (entering_statlen) { entering_statlen = false; statlen_entry = ""; }

    // --- KEY MAPPING ---
    switch (c) {
      case 'h': case 'H': print_help(); break;
      case 'P': print_params(); break;
      case 'S': 
        Serial.println(">>> Starting single sweep..."); 
        currentState = SWEEPING; 
        configure_radio_for_state(SWEEPING); 
        break;
      
      case '[': {
          int newv = (int)PRINT_RSSI_THRESH + 5; if (newv > -20) newv = -20;
          PRINT_RSSI_THRESH = (int8_t)newv; 
          Serial.print("RSSI print threshold = "); Serial.print(PRINT_RSSI_THRESH); Serial.println(" dBm");
          break; 
      }
      case ']': {
          int newv = (int)PRINT_RSSI_THRESH - 5; if (newv < -100) newv = -100;
          PRINT_RSSI_THRESH = (int8_t)newv; 
          Serial.print("RSSI print threshold = "); Serial.print(PRINT_RSSI_THRESH); Serial.println(" dBm");
          break;
      }
      case 'T': Serial.println("Enter RSSI threshold in dBm (e.g., -55) then Enter:"); entering_thresh = true; thresh_entry = ""; break;

      case '+': if (best_ch_found < MAX_CH) { best_ch_found++; set_channel(best_ch_found); } Serial.print("Channel -> "); Serial.println(best_ch_found); break;
      case '-': if (best_ch_found > MIN_CH) { best_ch_found--; set_channel(best_ch_found); } Serial.print("Channel -> "); Serial.println(best_ch_found); break;
      
      case 'c': 
        Serial.println("Enter channel number + Enter:"); 
        entering_channel = true; 
        chan_entry = ""; 
        break;

      // ---- Pipes ----
      case 'a': 
        promiscuous_mode = false; // Force Standard
        focused_pipe_idx = -1; 
        Serial.println(F("\nResetting focus to ALL pipes (Standard/HW Mode)"));
        if(use_preset_mode) configure_radio_for_state(LISTENING); 
        break;
        
      case '0' ... '7': 
        promiscuous_mode = false; // Force Standard
        focused_pipe_idx = c - '0'; 
        Serial.print("\nFocusing strictly on PIPE "); Serial.println(focused_pipe_idx);
        Serial.println("(Standard/HW Mode)");
        if(use_preset_mode) configure_radio_for_state(LISTENING);
        break;

      // ---- Mode Selection ----
      case 'A':
        run_smart_address_search();
        break;

      case 'n': 
        current_preset_idx++; if (current_preset_idx >= NUM_PRESETS) current_preset_idx = 0;
        use_preset_mode = true; 
        promiscuous_mode = false; // FORCE STANDARD ON PRESET (User Request)
        focused_pipe_idx = -1; 
        Serial.println(F("\nCycling Address Preset..."));
        Serial.print("Active Preset: ["); Serial.print(current_preset_idx); Serial.print("] "); Serial.println(PRESETS[current_preset_idx]->name);
        Serial.println(">>> STANDARD MODE ACTIVATED (Hardware Filtering on Preset)");
        configure_radio_for_state(LISTENING);
        if(currentState == IDLE) currentState = LISTENING;
        break;
        
      case 'M': 
        Serial.println("Enter full address (Prefix + Base) as hex bytes, space separated:"); 
        promiscuous_mode = false; // FORCE STANDARD ON MANUAL
        entering_address = true; addr_entry = ""; 
        break;

      // ---- Record / Fire ----
      case 'R': 
        if (currentState != LISTENING) { Serial.println("Must be in LISTENING mode to record."); break; }
        is_recording = !is_recording; 
        if(is_recording) { 
            recorded_packet_count=0; memset(recorded_packets,0,sizeof(RecordedPacket)*MAX_RECORDED_PACKETS); 
            digitalWrite(LED_PIN, LOW); // LED solid on
            Serial.print(">>> RECORDING ARMED. Clearing old packets. Max="); Serial.print(MAX_RECORDED_PACKETS); Serial.println(" packets.");
        }
        else { 
            digitalWrite(LED_PIN, HIGH); // LED off
            Serial.print(">>> RECORDING STOPPED. Captured "); Serial.print(recorded_packet_count); Serial.println(" packets."); 
        }
        break;
      case 'f': 
        if (is_recording) { Serial.println("Cannot 'fire' while recording is active. Press 'R' to stop first."); break; }
        if (recorded_packet_count == 0) { Serial.println("No packets recorded. Press 'R' to start/stop recording first."); break; }
        fire_recorded_packets(); 
        break;

      // ---- Sniffer Config ----
      case 'o': 
        clean_output_mode = !clean_output_mode; 
        Serial.print("Output: "); Serial.println(clean_output_mode ? "CLEAN (Payload Only)" : "VERBOSE"); 
        break;

      case 'L': 
        current_plen_mode = (current_plen_mode + 1) % 4; 
        apply_pcnf0_pcnf1(); 
        Serial.print("\nSwitching PLEN to mode: "); 
        Serial.print(current_plen_mode);
        switch(current_plen_mode) {
          case 0: Serial.println(F(" (8-bit)")); break;
          case 1: Serial.println(F(" (16-bit)")); break;
          case 2: Serial.println(F(" (32-bit Zero)")); break;
          case 3: Serial.println(F(" (Long Range)")); break;
        }
        configure_radio_for_state(LISTENING); 
        break;
      case 'W': 
        whitening_enabled = !whitening_enabled; apply_pcnf0_pcnf1(); 
        Serial.print("Whitening "); Serial.println(whitening_enabled ? "ENABLED" : "DISABLED"); 
        break;
      case 'D': 
        current_mode = (current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? RADIO_MODE_MODE_Nrf_1Mbit : RADIO_MODE_MODE_Nrf_2Mbit;
        NRF_RADIO->MODE = current_mode << RADIO_MODE_MODE_Pos; 
        set_channel(best_ch_found);
        Serial.print("Data rate: "); Serial.println((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2M" : "1M");
        break;
      case 'b': 
        BALEN = (BALEN % 4) + 1; apply_pcnf0_pcnf1(); set_channel(best_ch_found); 
        Serial.print("BALEN="); Serial.println(BALEN); 
        break;
      case 'l': 
        LFLEN = (LFLEN + 1) % 9; apply_pcnf0_pcnf1(); set_channel(best_ch_found); 
        Serial.print("LFLEN="); Serial.println(LFLEN); 
        break;
      case 's': 
        S1LEN = (S1LEN + 1) % 8; apply_pcnf0_pcnf1(); set_channel(best_ch_found); 
        Serial.print("S1LEN="); Serial.println(S1LEN); 
        break;
      case 't': 
        if (STATLEN==0) STATLEN=6; else if(STATLEN==6) STATLEN=8; else if(STATLEN==8) STATLEN=16; else if(STATLEN==16) STATLEN=24; else if(STATLEN==24) STATLEN=32; else if(STATLEN==32) STATLEN=64; else STATLEN=0;
        apply_pcnf0_pcnf1(); set_channel(best_ch_found); 
        Serial.print("STATLEN="); Serial.println(STATLEN); 
        break;
      case 'K': Serial.println("Enter exact STATLEN (0-255) then Enter:"); entering_statlen=true; statlen_entry=""; break;
      case 'C': 
        current_crc_len = (current_crc_len + 1) % 3; 
        configure_radio_for_state(LISTENING); 
        Serial.print("CRC set to: "); 
        if (current_crc_len == 0) Serial.println(F("DISABLED"));
        else if (current_crc_len == 1) Serial.println(F("1 Byte"));
        else if (current_crc_len == 2) Serial.println(F("2 Bytes"));
        break;
      case 'V': 
        crc_param_profile = (crc_param_profile + 1) % 4; 
        configure_radio_for_state(LISTENING); 
        Serial.print("CRC Profile set to: "); 
        switch (crc_param_profile) {
            case 0: Serial.println(F("0: Default (Poly:0x1021, Init:0xFFFF)")); break;
            case 1: Serial.println(F("1: Kermit  (Poly:0x1021, Init:0x0000)")); break;
            case 2: Serial.println(F("2: Modbus  (Poly:0x8005, Init:0xFFFF)")); break;
            case 3: Serial.println(F("3: ARC     (Poly:0x8005, Init:0x0000)")); break;
        }
        break;
      case 'e': 
        payload_endian_little = !payload_endian_little; apply_pcnf0_pcnf1(); 
        set_channel(best_ch_found);
        Serial.print("Payload Endian set to: "); Serial.println(payload_endian_little ? "Little (nRF)" : "Big (BLE)"); 
        break;
      case 'i': 
        crc_skip_addr = !crc_skip_addr; 
        configure_radio_for_state(LISTENING); 
        Serial.print("CRC Skip Address set to: "); Serial.println(crc_skip_addr ? "Skip (Payload Only)" : "Include (Addr + Payload)"); 
        break;
      case 'p': 
        header_parse_enabled = !header_parse_enabled; 
        Serial.print("Header parsing "); Serial.println(header_parse_enabled ? "ENABLED" : "DISABLED"); 
        break;
      case 'r': 
        Serial.println("Reapplying radio with current params..."); 
        configure_radio_for_state(LISTENING); 
        break;
      case '<': 
        bit_shift_amount = (bit_shift_amount - 1); if(bit_shift_amount<-7) bit_shift_amount=7; 
        Serial.print("Bit shift set to: "); Serial.println(bit_shift_amount); 
        break;
      case '>': 
        bit_shift_amount = (bit_shift_amount + 1); if(bit_shift_amount>7) bit_shift_amount=-7; 
        Serial.print("Bit shift set to: "); Serial.println(bit_shift_amount); 
        break;
      
      default: 
        if(isDigit(c)) { 
           // Ignore stray digits unless in entry mode
        } 
        else { Serial.print("Unknown key: "); Serial.println(c); }
        break;
    }
  }
}