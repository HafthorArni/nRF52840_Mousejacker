#include "shared.h"
#include <bluefruit.h>
#include <SPI.h>

// =============================================================================
//                             GLOBALS
// =============================================================================

// State Machine
volatile State currentState = IDLE;

// RSSI / Printing
int8_t PRINT_RSSI_THRESH = -90; 
static volatile int8_t  last_rssi_dbm = -127;
static volatile bool    rssi_ready    = false;

// Sweep Bookkeeping
static uint32_t ch_hits[(MAX_CH - MIN_CH + 1)];
uint8_t  best_ch_found = 50; 

// Radio Parameters
bool     whitening_enabled = false;
uint32_t current_mode      = RADIO_MODE_MODE_Nrf_2Mbit;
uint8_t  BALEN             = 1;  
uint8_t  LFLEN             = 0;  
uint8_t  S1LEN             = 0;  
uint8_t  STATLEN           = 32; 
uint8_t  current_crc_len   = 0;  
bool     header_parse_enabled = false;
bool     locked = false;
bool     payload_endian_little = false; 
uint8_t  crc_param_profile     = 0;     
bool     crc_skip_addr         = false;
int8_t   bit_shift_amount      = 0;     
bool     clean_output_mode     = false; 
uint8_t  current_plen_mode = 0; 
int8_t   focused_pipe_idx  = -1; 

// --- INTERNAL MODES ---
// "promiscuous_mode" here just means "Raw Capture Mode" (Software Validation)
bool promiscuous_mode = false; 
bool use_preset_mode = false; 

// Sniffer Buffer
static esb_rx_t esb_rx_buf;

// Temp buffers for Software Processing
uint8_t raw_rx_buffer[64];
uint8_t processing_buffer[64];

// Presets (LOGITacker optimized addresses)
static const AddressPreset PRESET_LOGITACKER = {
    "LOGI", false, {0xA8, 0xA8, 0xA8, 0xA8}, {0xAA, 0xAA, 0xAA, 0xAA}, 
    {0xAA, 0x1F, 0x9F, 0xA8, 0xAF, 0xA9, 0x8F, 0xAA}
};
static const AddressPreset PRESET_PURE = {
    "PURE PREAMBLE", false, {0x55, 0x55, 0x55, 0x55}, {0xAA, 0xAA, 0xAA, 0xAA}, 
    {0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA} 
};
static const AddressPreset PRESET_CALC = {
    "CALC", false, {0x5A, 0x5A, 0x5A, 0x5A}, {0xA5, 0xA5, 0xA5, 0xA5}, 
    {0x2A, 0x4A, 0x52, 0x54, 0xAB, 0xAD, 0xB5, 0xD5} 
};
static const AddressPreset PRESET_ZERO_BASE = {
    "ZERO+BASE", true, {0x00, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x00}, 
    {0xAA, 0x55, 0xAB, 0x56, 0xA8, 0x54, 0x0F, 0xF0} 
};

// Global Array pointers
const AddressPreset* PRESETS[] = { &PRESET_LOGITACKER, &PRESET_PURE, &PRESET_CALC, &PRESET_ZERO_BASE };
const uint8_t NUM_PRESETS = 4;
uint8_t current_preset_idx = 0;

// Discovery State
static const uint16_t SCAN_DWELL_MS = 200;
static volatile uint32_t scan_pkt_count  = 0;
static volatile uint32_t scan_addr_count = 0;
static bool suppress_prints = false;
bool     have_prefix = false;
uint8_t  discovered_prefix = 0xAA;
uint8_t  discovered_base[4] = {0};
uint8_t  discovered_count = 0;

// Smart Scan Results
struct AddrCandidate {
    uint8_t addr[5];
    uint32_t hits;
    uint8_t preset_idx;
};
AddrCandidate candidates[10]; 
uint8_t candidate_count = 0;

// Recording
RecordedPacket recorded_packets[MAX_RECORDED_PACKETS];
uint16_t recorded_packet_count = 0;
bool is_recording = false;

// =============================================================================
//                             HELPERS (INTERNAL)
// =============================================================================

static uint32_t bytewise_bit_swap(uint8_t const * p_inp) {
  uint32_t inp = (p_inp[3] << 24) | (p_inp[2] << 16) | (p_inp[1] << 8) | (p_inp[0]);
  inp = (inp & 0xF0F0F0F0) >> 4 | (inp & 0x0F0F0F0F) << 4;
  inp = (inp & 0xCCCCCCCC) >> 2 | (inp & 0x33333333) << 2;
  inp = (inp & 0xAAAAAAAA) >> 1 | (inp & 0x55555555) << 1;
  return inp;
}

static uint32_t addr_conv(uint8_t const* p_addr, bool raw) {
  if (raw) return (p_addr[0] << 24) | (p_addr[1] << 16) | (p_addr[2] << 8) | p_addr[3];
  uint32_t bit_swapped = bytewise_bit_swap(p_addr);
  return ((bit_swapped & 0xFF000000) >> 24) | ((bit_swapped & 0x00FF0000) >> 8) |
         ((bit_swapped & 0x0000FF00) << 8)  | ((bit_swapped & 0x000000FF) << 24);
}

// -----------------------------------------------------------------------------
// NEW: Software Processing Helpers (LOGITacker Logic)
// -----------------------------------------------------------------------------

// Standard CRC-16-CCITT (Poly 0x1021, Init 0xFFFF)
uint16_t calc_esb_crc(const uint8_t* data, uint16_t len) {
    uint16_t crc = 0xFFFF;
    for (uint16_t i = 0; i < len; i++) {
        crc  = (uint8_t)(crc >> 8) | (crc << 8);
        crc ^= data[i];
        crc ^= (uint8_t)(crc & 0xff) >> 4;
        crc ^= (crc << 8) << 4;
        crc ^= ((crc & 0xff) << 4) << 1;
    }
    return crc;
}

// Destructive left shift by 'shift' bits
static void apply_bit_shift_buffer(uint8_t* buffer, size_t len, uint8_t shift) {
    if (shift == 0) return;
    for (size_t i = 0; i < len; i++) {
        uint8_t next = (i + 1 < len) ? buffer[i+1] : 0;
        buffer[i] = (buffer[i] << shift) | (next >> (8 - shift));
    }
}

/**
 * Validates a raw buffer by looking for a valid CRC16.
 * It assumes a 5-byte address + 9-bit PCF + Payload + 2-byte CRC.
 * Returns the payload length if valid, -1 if invalid.
 * * missing_byte_mode: If true, assumes the buffer passed is 61 bytes and index 0 is the reconstructed byte.
 */
int check_buffer_crc_logic(uint8_t* buf, uint8_t buf_len, bool missing_byte_mode) {
    // We scan offset 0..2 for start of packet to handle minor jitter
    for (uint8_t offset = 0; offset < 3; offset++) {
        uint8_t* pkt = &buf[offset];
        
        uint8_t pcf_index = 5; 
        
        if (offset + pcf_index >= buf_len) break;

        // PCF is 9 bits. The Length is the top 6 bits of the first PCF byte.
        uint8_t pcf_len = pkt[pcf_index] >> 2;
        
        // Sanity Check: Max payload 32
        if (pcf_len > 32) continue; 
        
        // Total Packet Length for CRC = Addr(5) + PCF(approx 2) + Payload
        uint8_t total_data_len = 5 + 1 + pcf_len; // 5 addr + 1 PCF + payload
        
        if (offset + total_data_len + 2 > buf_len) continue;

        uint16_t calced = calc_esb_crc(pkt, total_data_len);
        uint16_t received = (pkt[total_data_len] << 8) | pkt[total_data_len+1];
        
        if (calced == received) return pcf_len;
    }
    return -1;
}

// =============================================================================
//                           LOW LEVEL RADIO CONTROL
// =============================================================================

static inline void radio_disable() {
  NRF_RADIO->TASKS_DISABLE = 1;
  while (NRF_RADIO->EVENTS_DISABLED == 0) {}
  NRF_RADIO->EVENTS_DISABLED = 0;
}

void apply_pcnf0_pcnf1() {
  NRF_RADIO->PCNF0 =
    (0 << RADIO_PCNF0_S0LEN_Pos) |
    (LFLEN << RADIO_PCNF0_LFLEN_Pos) |
    (S1LEN << RADIO_PCNF0_S1LEN_Pos) |
    (current_plen_mode << RADIO_PCNF0_PLEN_Pos);

  uint32_t pcnf1 = 0;
  pcnf1 |= (whitening_enabled ? RADIO_PCNF1_WHITEEN_Enabled : RADIO_PCNF1_WHITEEN_Disabled) << RADIO_PCNF1_WHITEEN_Pos;
  pcnf1 |= (payload_endian_little ? RADIO_PCNF1_ENDIAN_Little : RADIO_PCNF1_ENDIAN_Big) << RADIO_PCNF1_ENDIAN_Pos;
  pcnf1 |= (BALEN << RADIO_PCNF1_BALEN_Pos); 
  pcnf1 |= (STATLEN << RADIO_PCNF1_STATLEN_Pos);
  pcnf1 |= (RADIO_MAX_PAYLOAD << RADIO_PCNF1_MAXLEN_Pos);
  NRF_RADIO->PCNF1 = pcnf1;
}

void set_channel(uint8_t ch) {
  radio_disable();
  NRF_RADIO->FREQUENCY = ch;
  NRF_RADIO->EVENTS_READY   = 0;
  NRF_RADIO->EVENTS_ADDRESS = 0;
  NRF_RADIO->EVENTS_END     = 0;
  NRF_RADIO->EVENTS_RSSIEND = 0;

  rssi_ready    = false;
  last_rssi_dbm = -127;
  memset(&esb_rx_buf, 0, sizeof(esb_rx_buf));
  NRF_RADIO->PACKETPTR = (uint32_t)&esb_rx_buf;
  NRF_RADIO->TASKS_RXEN = 1;
}

void radio_base_config() {
  NRF_CLOCK->EVENTS_HFCLKSTARTED = 0;
  NRF_CLOCK->TASKS_HFCLKSTART = 1;
  while (NRF_CLOCK->EVENTS_HFCLKSTARTED == 0) {}

  NRF_RADIO->MODE = current_mode << RADIO_MODE_MODE_Pos;

  if (promiscuous_mode) {
      // --- RAW CAPTURE MODE (Software Validation) ---
      // Force Raw Capture settings regardless of globals
      NRF_RADIO->PCNF0 = 
          (0 << RADIO_PCNF0_S0LEN_Pos) |
          (0 << RADIO_PCNF0_LFLEN_Pos) | // RAW: No Length Parsing
          (0 << RADIO_PCNF0_S1LEN_Pos) |
          (0 << RADIO_PCNF0_PLEN_Pos) |  // Standard Preamble
          (0 << RADIO_PCNF0_CRCINC_Pos); // RAW: No HW CRC

      NRF_RADIO->PCNF1 = 
          (RADIO_PCNF1_WHITEEN_Disabled << RADIO_PCNF1_WHITEEN_Pos) |
          (RADIO_PCNF1_ENDIAN_Big << RADIO_PCNF1_ENDIAN_Pos) |
          (1 << RADIO_PCNF1_BALEN_Pos) | // RAW: Strip only 1 byte (the trigger)
          (0 << RADIO_PCNF1_STATLEN_Pos) |
          (60 << RADIO_PCNF1_MAXLEN_Pos); // RAW: Capture everything
  } else {
      // --- STANDARD MODE (Hardware Filtering) ---
      NRF_RADIO->PCNF0 = 0;
      NRF_RADIO->PCNF1 = 0;
      apply_pcnf0_pcnf1();
  }

  if (use_preset_mode) {
      const AddressPreset* p = PRESETS[current_preset_idx];
      NRF_RADIO->BASE0 = addr_conv(p->base0, p->raw_mode);
      NRF_RADIO->BASE1 = addr_conv(p->base1, p->raw_mode);
      
      if (p->raw_mode) {
          NRF_RADIO->PREFIX0 = (p->prefixes[3] << 24) | (p->prefixes[2] << 16) | (p->prefixes[1] << 8) | p->prefixes[0];
          NRF_RADIO->PREFIX1 = (p->prefixes[7] << 24) | (p->prefixes[6] << 16) | (p->prefixes[5] << 8) | p->prefixes[4];
      } else {
          NRF_RADIO->PREFIX0 = bytewise_bit_swap(&p->prefixes[0]);
          NRF_RADIO->PREFIX1 = bytewise_bit_swap(&p->prefixes[4]);
      }

      // In Raw Capture mode, we enable all pipes to catch the prefix
      NRF_RADIO->RXADDRESSES = promiscuous_mode ? 0xFF : (1 << ((focused_pipe_idx == -1) ? 0 : focused_pipe_idx));

  } else {
      // Manual/Discovery Mode
      NRF_RADIO->BASE0 = 0; NRF_RADIO->BASE1 = 0;
      if (have_prefix) {
        NRF_RADIO->PREFIX0 = discovered_prefix;
        NRF_RADIO->PREFIX1 = 0;
        NRF_RADIO->RXADDRESSES = (1 << 0); 

        uint32_t final_base = 0;
        for(uint8_t i=0; i<discovered_count; i++) {
          final_base |= ((uint32_t)discovered_base[i]) << (8*i);
        }
        NRF_RADIO->BASE0 = final_base;
      } else {
        NRF_RADIO->PREFIX0  = 0xAA; 
        NRF_RADIO->PREFIX1  = 0;
        NRF_RADIO->RXADDRESSES = (1 << 0); 
      }
  }

  // CRC Config
  if (promiscuous_mode) {
      // Disable Hardware CRC (we do it in software)
      NRF_RADIO->CRCCNF = (RADIO_CRCCNF_LEN_Disabled << RADIO_CRCCNF_LEN_Pos);
  } else {
      switch (crc_param_profile) {
        case 0: NRF_RADIO->CRCPOLY = 0x00001021UL; NRF_RADIO->CRCINIT = 0x0000FFFFUL; break;
        case 1: NRF_RADIO->CRCPOLY = 0x00001021UL; NRF_RADIO->CRCINIT = 0x00000000UL; break;
        case 2: NRF_RADIO->CRCPOLY = 0x00008005UL; NRF_RADIO->CRCINIT = 0x0000FFFFUL; break;
        case 3: NRF_RADIO->CRCPOLY = 0x00008005UL; NRF_RADIO->CRCINIT = 0x00000000UL; break;
      }
      uint32_t crc_val = RADIO_CRCCNF_LEN_Disabled;
      if (current_crc_len == 1) crc_val = RADIO_CRCCNF_LEN_One;
      else if (current_crc_len == 2) crc_val = RADIO_CRCCNF_LEN_Two;

      uint32_t crc_conf_val = (crc_val << RADIO_CRCCNF_LEN_Pos);
      if (crc_skip_addr) {
        crc_conf_val |= (RADIO_CRCCNF_SKIPADDR_Skip << RADIO_CRCCNF_SKIPADDR_Pos);
      }
      NRF_RADIO->CRCCNF = crc_conf_val;
  }

  NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_END_START_Msk;
  NRF_RADIO->MODECNF0 = (RADIO_MODECNF0_RU_Fast << RADIO_MODECNF0_RU_Pos);

  memset(&esb_rx_buf, 0, sizeof(esb_rx_buf));
  NRF_RADIO->PACKETPTR = (uint32_t)&esb_rx_buf;
}

void configure_radio_for_state(State s) {
  radio_disable();
  radio_base_config();
  if (s == SWEEPING)       set_channel(MIN_CH);
  else if (s == LISTENING) set_channel(best_ch_found);
}

static void restore_single_pipe_prefix(uint8_t prefix) {
  NRF_RADIO->PREFIX0 = prefix;
  NRF_RADIO->PREFIX1 = 0;
  NRF_RADIO->RXADDRESSES = (1 << 0);
  NRF_RADIO->BASE0 = 0x00000000UL;
  NRF_RADIO->BASE1 = 0x00000000UL;
}

// =============================================================================
//                       SMART ADDRESS AUTO-SCANNER
// =============================================================================

void add_candidate(uint8_t* addr) {
    // Check if exists
    for (int i=0; i<candidate_count; i++) {
        if (memcmp(candidates[i].addr, addr, 5) == 0) {
            candidates[i].hits++;
            return;
        }
    }
    // Add new
    if (candidate_count < 10) {
        memcpy(candidates[candidate_count].addr, addr, 5);
        candidates[candidate_count].hits = 1;
        candidates[candidate_count].preset_idx = current_preset_idx;
        candidate_count++;
    }
}

void run_smart_address_search() {
    Serial.println(F("\n========================================"));
    Serial.println(F("   SMART ADDRESS DISCOVERY (AUTO)"));
    Serial.println(F("========================================"));
    Serial.println(F("Scanning continuously until an address is found..."));
    Serial.println(F("Press 'z' to abort."));
    
    // Setup
    use_preset_mode = true;
    promiscuous_mode = true; // Use Raw Capture for discovery
    candidate_count = 0;
    suppress_prints = true; 
    
    // Continuous Loop until Candidate found or Abort
    while (candidate_count == 0) {
        
        // Loop through all presets
        for (uint8_t p_idx = 0; p_idx < NUM_PRESETS; p_idx++) {
            current_preset_idx = p_idx;
            Serial.print(F("Scanning [")); Serial.print(PRESETS[p_idx]->name); Serial.print(F("]... "));
            
            // Reconfigure radio for this preset
            configure_radio_for_state(LISTENING); 
            
            uint32_t t0 = millis();
            uint32_t packets_checked = 0;
            uint32_t local_hits = 0;
            
            // Dwell for 3 seconds per preset
            while (millis() - t0 < 3000) {
                
                // Poll hardware directly 
                if (NRF_RADIO->EVENTS_END) {
                    NRF_RADIO->EVENTS_END = 0;
                    packets_checked++;
                    
                    // Get Raw
                    memcpy(raw_rx_buffer, (uint8_t*)&esb_rx_buf, 60);
                    
                    // Software Validation Loop
                    for (uint8_t shift = 0; shift < 8; shift++) {
                        memcpy(processing_buffer, raw_rx_buffer, 60);
                        apply_bit_shift_buffer(processing_buffer, 60, shift);
                        
                        // 1. Standard Check
                        int len = check_buffer_crc_logic(processing_buffer, 60, false);
                        
                        // 2. Missing Byte Repair
                        if (len == -1) {
                            uint8_t repaired[61];
                            memcpy(&repaired[1], processing_buffer, 60);
                            for (int g = 0; g < 256; g++) {
                                repaired[0] = (uint8_t)g;
                                if (check_buffer_crc_logic(repaired, 61, true) != -1) {
                                    len = 100; 
                                    memcpy(processing_buffer, repaired, 60); 
                                    break;
                                }
                            }
                        }
                        
                        if (len != -1) {
                            local_hits++;
                            add_candidate(processing_buffer); // Add to stats
                            break; 
                        }
                    }
                    
                    // Flush RX
                    NRF_RADIO->TASKS_DISABLE = 1; 
                    while(NRF_RADIO->EVENTS_DISABLED==0); NRF_RADIO->EVENTS_DISABLED=0; 
                    NRF_RADIO->TASKS_RXEN = 1;

                    // If we found a candidate, stop scanning immediately
                    if (local_hits > 0) goto report;
                }
                
                // Check for exit
                if (Serial.available() && Serial.read() == 'z') {
                    Serial.println(F("\nAborted by user."));
                    goto report;
                }
            }
            Serial.print(F("Pkts: ")); Serial.println(packets_checked); 
        }
        Serial.println(F("... cycling presets (Press 'z' to abort) ..."));
    }
    
report:
    // REPORT
    Serial.println(F("\n--- DISCOVERY RESULTS ---"));
    if (candidate_count == 0) {
        Serial.println(F("No valid addresses found."));
    } else {
        Serial.println(F("SUCCESS: Address Found!"));
        for (int i=0; i<candidate_count; i++) {
            Serial.print(i); Serial.print(F(": Address: "));
            for(int j=0; j<5; j++) {
                if(candidates[i].addr[j]<0x10) Serial.print("0");
                Serial.print(candidates[i].addr[j], HEX); Serial.print(" ");
            }
            Serial.print(F(" [")); Serial.print(PRESETS[candidates[i].preset_idx]->name);
            Serial.print(F("] Hits: ")); Serial.println(candidates[i].hits);
        }
        Serial.println(F("\nType 'M' then the address to lock on it."));
    }
    Serial.println(F("========================================"));
    
    // Return to simple monitoring
    suppress_prints = false;
    configure_radio_for_state(LISTENING);
}

// =============================================================================
//                             EVENT PROCESSING
// =============================================================================

void poll_radio_events(uint8_t channel, bool allow_prints) {
  // 1. RSSI Handling (Common)
  if (NRF_RADIO->EVENTS_ADDRESS) {
    NRF_RADIO->EVENTS_ADDRESS = 0;
    rssi_ready = false;
    NRF_RADIO->EVENTS_RSSIEND = 0;
    NRF_RADIO->TASKS_RSSISTART = 1;
  }
  if (NRF_RADIO->EVENTS_RSSIEND) {
    NRF_RADIO->EVENTS_RSSIEND = 0;
    uint8_t raw = NRF_RADIO->RSSISAMPLE;
    last_rssi_dbm = -(int8_t)raw;
    rssi_ready = true;
  }

  // 2. Packet End Handling
  if (NRF_RADIO->EVENTS_END) {
    NRF_RADIO->EVENTS_END = 0;
    scan_pkt_count++;

    // -------------------------------------------------------------------------
    // BRANCH A: RAW CAPTURE (Software Validation)
    // -------------------------------------------------------------------------
    if (promiscuous_mode) {
        // Copy raw hardware buffer to safe buffer
        memcpy(raw_rx_buffer, (uint8_t*)&esb_rx_buf, 60);

        bool packet_found = false;

        // Try Bit-Shifts 0..7
        for (uint8_t shift = 0; shift < 8; shift++) {
            
            // Create shifted view
            memcpy(processing_buffer, raw_rx_buffer, 60);
            apply_bit_shift_buffer(processing_buffer, 60, shift);

            // Try Standard Validation
            int len = check_buffer_crc_logic(processing_buffer, 60, false);
            
            // Try Missing Byte Repair (0..255 guess)
            if (len == -1) {
                uint8_t repaired_buffer[61];
                memcpy(&repaired_buffer[1], processing_buffer, 60);

                for (int guess = 0; guess < 256; guess++) {
                    repaired_buffer[0] = (uint8_t)guess;
                    len = check_buffer_crc_logic(repaired_buffer, 61, true); 
                    if (len != -1) {
                        memcpy(processing_buffer, repaired_buffer, 60);
                        break;
                    }
                }
            }

            if (len != -1) {
                // Packet Validated via Software CRC
                packet_found = true;
                scan_addr_count++;
                
                if (allow_prints && !suppress_prints) {
                    const AddressPreset* p = PRESETS[current_preset_idx];
                    Serial.print(F("HIT [")); Serial.print(p->name); Serial.print(F("] Shift=")); Serial.print(shift);
                    Serial.print(F(" Addr:"));
                    // Print 5 bytes of address
                    for(int i=0; i<5; i++) {
                        if(processing_buffer[i]<0x10) Serial.print("0");
                        Serial.print(processing_buffer[i], HEX); Serial.print(" ");
                    }
                    Serial.print(F(" Len=")); Serial.print(len);
                    Serial.print(F(" Payload:"));
                    for (int i=0; i<len; i++) {
                         uint8_t b = processing_buffer[7+i];
                         if(b<0x10) Serial.print("0");
                         Serial.print(b, HEX); Serial.print(" ");
                    }
                    Serial.println();
                }
                break; // Found the packet, stop shifting
            }
        }
    }
    // -------------------------------------------------------------------------
    // BRANCH B: STANDARD MODE (Hardware Validation)
    // -------------------------------------------------------------------------
    else {
        int8_t rssi = rssi_ready ? last_rssi_dbm : -127;
        
        bool hw_crc_passed = (NRF_RADIO->CRCSTATUS == 1);
        bool crc_disabled  = (current_crc_len == 0);
        bool packet_accepted = crc_disabled ? true : hw_crc_passed;

        if (rssi_ready && rssi >= PRINT_RSSI_THRESH && packet_accepted) {
          scan_addr_count++;

          // Payload Ptr logic
          uint8_t* payload_start_ptr;
          size_t   payload_actual_len;
          size_t   max_payload_bytes_in_buffer;

          if (LFLEN > 0) {
            uint8_t lmask = (LFLEN >= 8) ? 0xFFu : (uint8_t)((1u << LFLEN) - 1u);
            payload_actual_len = (size_t)(esb_rx_buf.LENGTH & lmask);
            if (S1LEN > 0) {
              payload_start_ptr = esb_rx_buf.payload;
              max_payload_bytes_in_buffer = RADIO_MAX_PAYLOAD;
            } else {
              payload_start_ptr = &esb_rx_buf.S1;
              max_payload_bytes_in_buffer = RADIO_MAX_PAYLOAD + 1;
            }
          } else {
            payload_start_ptr = (uint8_t*)&esb_rx_buf.LENGTH;
            max_payload_bytes_in_buffer = RADIO_MAX_PAYLOAD + 2; 
            payload_actual_len = (STATLEN == 0 || STATLEN > max_payload_bytes_in_buffer)
                                 ? max_payload_bytes_in_buffer : STATLEN;
          }
          if (payload_actual_len > max_payload_bytes_in_buffer) payload_actual_len = max_payload_bytes_in_buffer;
          if (payload_actual_len > MAX_PDU_SIZE) payload_actual_len = MAX_PDU_SIZE; 

          // --- RECORDING ---
          if (is_recording && recorded_packet_count < MAX_RECORDED_PACKETS) {        
            size_t pdu_total_len = (LFLEN > 0) ? (1 + (S1LEN>0?1:0) + payload_actual_len) : payload_actual_len;
            if (pdu_total_len > MAX_RECORDED_PAYLOAD) pdu_total_len = MAX_RECORDED_PAYLOAD;
            if (pdu_total_len > 0) {
              recorded_packets[recorded_packet_count].len = (uint8_t)pdu_total_len;
              memcpy(recorded_packets[recorded_packet_count].data, payload_start_ptr, pdu_total_len);
              recorded_packets[recorded_packet_count].timestamp_ms = millis();
              recorded_packet_count++;
              digitalWrite(LED_PIN, HIGH); delay(10); digitalWrite(LED_PIN, LOW);
            }
          }

          // --- PRINTING ---
          if (allow_prints && !suppress_prints) {
            uint8_t pipe = NRF_RADIO->RXMATCH & 0x07;
            if (!clean_output_mode) {
                print_ts();
                Serial.print("Ch "); Serial.print(channel);
                Serial.print(" pipe="); Serial.print(pipe);
                Serial.print(" RSSI="); Serial.print(rssi); Serial.print(" dBm");
                
                // Hide CRC output unless enabled
                if (!crc_disabled) {
                    Serial.print(hw_crc_passed ? " CRC=OK " : " CRC=BAD ");
                }
            }

            if (bit_shift_amount != 0) {
               uint8_t shifted_payload[MAX_PDU_SIZE];
               size_t len_to_process = (payload_actual_len > MAX_PDU_SIZE) ? MAX_PDU_SIZE : payload_actual_len;
               if (len_to_process > 0) {
                  memcpy(shifted_payload, payload_start_ptr, len_to_process);
                  apply_bit_shift_buffer(shifted_payload, len_to_process, bit_shift_amount); 
                  print_hex(shifted_payload, len_to_process);
               }
            } else {
               print_hex(payload_start_ptr, payload_actual_len);
            }
          }
        }
    } // End Standard Mode

    // Reset Buffer for next packet
    memset(&esb_rx_buf, 0, sizeof(esb_rx_buf));
    rssi_ready = false;
    last_rssi_dbm = -127;
  }
}

// =============================================================================
//                             SWEEPING
// =============================================================================

static inline void start_rx_for_sweep(uint8_t ch) {
  set_channel(ch);
  NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_END_START_Msk;
}

uint8_t sweep_once_find_best() {
  memset(ch_hits, 0, sizeof(ch_hits));
  uint16_t best_hits = 0;
  uint8_t  best_ch   = 0;

  for (uint8_t ch = MIN_CH; ch <= MAX_CH; ++ch) {
    start_rx_for_sweep(ch);
    unsigned long t0 = millis();
    uint16_t local_hits = 0;

    while (millis() - t0 < DWELL_MS) {
      if (NRF_RADIO->EVENTS_ADDRESS) {
        NRF_RADIO->EVENTS_ADDRESS = 0;
        rssi_ready = false;
        NRF_RADIO->EVENTS_RSSIEND = 0;
        NRF_RADIO->TASKS_RSSISTART = 1;
      }
      if (NRF_RADIO->EVENTS_RSSIEND) {
        NRF_RADIO->EVENTS_RSSIEND = 0;
        last_rssi_dbm = -(int8_t)NRF_RADIO->RSSISAMPLE;
        rssi_ready = true;
      }
      if (NRF_RADIO->EVENTS_END) {
        NRF_RADIO->EVENTS_END = 0;
        
        // In raw capture mode, counting raw interrupts is enough for activity detection
        if (promiscuous_mode) {
             local_hits++; 
        } else {
            bool crc_ok = (current_crc_len == 0) ? true : (NRF_RADIO->CRCSTATUS == 1);
            if (rssi_ready && last_rssi_dbm >= PRINT_RSSI_THRESH && crc_ok) {
              local_hits++;
            }
        }
        rssi_ready = false;
        last_rssi_dbm = -127;
      }
    }
    ch_hits[ch - MIN_CH] = local_hits;
    if (local_hits > best_hits) { best_hits = local_hits; best_ch = ch; }
  }

  if (best_hits > 0) { best_ch_found = best_ch; return best_ch; }
  return 0;
}

// =============================================================================
//                             REPLAY / MANUAL
// =============================================================================

void fire_recorded_packets() {
  if (recorded_packet_count == 0) { Serial.println("No packets to fire. Press 'R' to start/stop recording first."); return; }
  
  // Disable raw capture mode for TX
  bool saved_promisc = promiscuous_mode;
  promiscuous_mode = false;

  radio_disable();
  radio_base_config(); 
  NRF_RADIO->TXADDRESS = 0; 
  NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk;
  
  Serial.print(">>> Firing "); Serial.print(recorded_packet_count); Serial.println(" recorded packets...");
  Serial.print("Firing on Ch: "); Serial.print(best_ch_found);
  Serial.print(", Rate: "); Serial.println((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2M" : "1M");
  
  NRF_RADIO->FREQUENCY = best_ch_found;
  
  uint32_t tx_start_time_ms = millis();
  uint32_t rx_start_time_ms = recorded_packets[0].timestamp_ms;

  for (uint16_t i = 0; i < recorded_packet_count; i++) {
    if (recorded_packets[i].len == 0) continue;
    
    // Timed transmission logic
    uint32_t target = tx_start_time_ms + (recorded_packets[i].timestamp_ms - rx_start_time_ms);
    while (millis() < target) delay(1);
    
    NRF_RADIO->PACKETPTR = (uint32_t)recorded_packets[i].data;
    
    // If static length, we must update STATLEN per packet
    if (LFLEN == 0) {
      uint32_t pcnf1 = NRF_RADIO->PCNF1 & ~(RADIO_PCNF1_STATLEN_Msk);
      pcnf1 |= (recorded_packets[i].len << RADIO_PCNF1_STATLEN_Pos);
      NRF_RADIO->PCNF1 = pcnf1;
    }
    
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->TASKS_TXEN = 1;
    
    unsigned long w = millis();
    while (NRF_RADIO->EVENTS_END == 0 && (millis() - w < 50)) {}
    NRF_RADIO->EVENTS_END = 0;
    
    NRF_RADIO->TASKS_DISABLE = 1;
    while (NRF_RADIO->EVENTS_DISABLED == 0) {}
    NRF_RADIO->EVENTS_DISABLED = 0;
  }
  Serial.println("TX complete. Re-enabling sniffer...");
  
  promiscuous_mode = saved_promisc; // Restore mode
  configure_radio_for_state(LISTENING);
}

void set_manual_address(String s) {
  s.trim();
  if (s.length() == 0) { Serial.println("Address string empty."); return; }
  use_preset_mode = false; 
  promiscuous_mode = false; // Disable Raw Capture for manual addressing

  have_prefix = false;
  discovered_count = 0;
  memset(discovered_base, 0, sizeof(discovered_base));

  int start_idx = 0;
  int end_idx = s.indexOf(' ');
  bool first_byte = true;
  uint32_t final_base = 0;

  while (start_idx < (int)s.length()) {
    if (end_idx == -1) end_idx = s.length();
    String byte_str = s.substring(start_idx, end_idx);
    byte_str.trim();
    if (byte_str.length() > 0) {
      byte b = (byte)strtoul(byte_str.c_str(), NULL, 16);
      if (first_byte) {
        discovered_prefix = b; have_prefix = true; first_byte = false;
      } else if (discovered_count < 4) {
        discovered_base[discovered_count] = b;
        final_base |= ((uint32_t)b) << (8 * discovered_count);
        discovered_count++;
      }
    }
    start_idx = end_idx + 1;
    if (start_idx >= (int)s.length()) break;
    end_idx = s.indexOf(' ', start_idx);
  }
  BALEN = (discovered_count == 0) ? 1 : discovered_count;
  
  configure_radio_for_state(LISTENING);
  if (currentState == IDLE) {
      Serial.println(">>> IDLE exit: Manual address set.");
      currentState = LISTENING;
  }
  
  Serial.println(">>> Manual address set.");
  print_params();
}

// =============================================================================
//                             SETUP & LOOP
// =============================================================================

void setup() {
  pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, HIGH);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  Serial.begin(SERIAL_BAUD);
  unsigned long t0 = millis();
  while (!Serial && millis() - t0 < 1500) {}

  Serial.println("\n--- nRF52840 Sniffer + Transmitter Test Bench (Hybrid Mode) ---");
  Serial.println("<<< nRF24 (TX) and nRF52 (Sniffer) running on same board >>>");

  configure_target_transmitter();
  
  Serial.println("\nInternal nRF52 (Sniffer) ready.");
  Serial.println("Press 'S' to sweep, then 'A' to Smart Auto-Scan.");
  print_help();

  radio_disable();
  currentState = IDLE;
}

bool btn_prev = false;
static bool tx_ok_logged = false; 

void loop() {
  // 1. Target TX
  run_target_transmitter();

  // DIAGNOSTIC
  if (!tx_ok_logged) {
    char tx[TARGET_RADIO_PAYLOAD_SIZE] = {0};
    if (radio.write(&tx, 0)) {
      Serial.println("\n>>> TX DIAGNOSTIC: radio.write() Succeeded. Transmitter is likely working.\n");
      tx_ok_logged = true;
    }
  }

  // 2. Button Check
  bool btn = (digitalRead(BUTTON_PIN) == LOW);
  if (btn && !btn_prev) {
    delay(20);
    if (digitalRead(BUTTON_PIN) == LOW) {
      Serial.println(">>> Button: starting single sweep...");
      if (is_recording) { 
        is_recording = false; 
        digitalWrite(LED_PIN, HIGH); 
        Serial.println(">>> Recording stopped by sweep button.");
      }
      currentState = SWEEPING; configure_radio_for_state(SWEEPING);
    }
  }
  btn_prev = btn;

  // 3. Serial
  serial_commands();

  // 4. State Machine
  switch (currentState) {
    case IDLE: delay(1); break;
    case SWEEPING: {
      uint8_t found = sweep_once_find_best();
      currentState = ANALYZING; radio_disable();
      Serial.println("\n--- Sweep done ---");
      if (found) { Serial.print("Best channel: "); Serial.println(found); }
      else { Serial.println("No channel activity found."); }
      break;
    }
    case ANALYZING:
      if (best_ch_found) {
        locked = true;
        // Logic check: If using presets, enable raw capture for better sniffing
        if (use_preset_mode) promiscuous_mode = true;
        
        configure_radio_for_state(LISTENING);
        Serial.print(">>> Locked to channel "); Serial.println(best_ch_found);
        if (promiscuous_mode) Serial.println(">>> RAW CAPTURE MODE ACTIVE (Software Validation)");
        else Serial.println(">>> STANDARD MODE ACTIVE (Hardware Validation)");
        
        currentState = LISTENING;
      } else {
        locked = false;
        currentState = IDLE; 
        Serial.println(">>> Returning to IDLE. Press 'S' to sweep again.");
      }
      break;
    case LISTENING:
      poll_radio_events(best_ch_found, /*allow_prints=*/true);
      break;
  }
}