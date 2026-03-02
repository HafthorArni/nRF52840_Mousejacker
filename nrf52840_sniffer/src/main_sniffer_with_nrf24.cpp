/*
  nRF52840 Ultimate Sniffer & Test Bench (Fully Upgraded)
  
  Hardware:
  - Adafruit Feather nRF52840 (Sniffer)
  - External nRF24L01+ (Target Transmitter) on pins 9 (CE), 10 (CSN)

  added interrupt-based 
*/

#include <Arduino.h>
#include <bluefruit.h>
#include <SPI.h>
#include <nRF24L01.h>
#include <RF24.h>

// =============================================================================
//                                 CONFIGURATION
// =============================================================================

// ---------------- Pins / Serial ----------------
#define LED_PIN       LED_BUILTIN
#define BUTTON_PIN    7
#define SERIAL_BAUD   250000

// ---------------- nRF24 (Target Sender) Config -----------------
#define RF24_CE_PIN   9
#define RF24_CSN_PIN  10

// nRF24 Object
RF24 radio(RF24_CE_PIN, RF24_CSN_PIN);

#define TARGET_RF_CHANNEL         50
#define TARGET_RADIO_PAYLOAD_SIZE 32
static const uint8_t target_rf_address[5] = { 0xE7, 0xE7, 0xE7, 0xE7, 0xE7 };

// ---------------- Sweep Config -----------------
#define MIN_CH        2      // 2402 MHz
#define MAX_CH        80     // 2480 MHz
#define DWELL_MS      100    // per-channel dwell

// ---------------- Sniffer Buffer -----------------
#define RADIO_MAX_PAYLOAD 62

typedef struct __attribute__((packed)) {
  uint8_t LENGTH;
  uint8_t S1;
  uint8_t payload[RADIO_MAX_PAYLOAD];
} esb_rx_t;

static esb_rx_t esb_rx_buf;

// Capture ceiling for recording/printing
#define MAX_PDU_SIZE (sizeof(esb_rx_t))

// =============================================================================
//                            GLOBAL VARIABLES & STATE
// =============================================================================

// ---------------- State Machine ----------------
enum State { IDLE, SWEEPING, ANALYZING, LISTENING };
static volatile State currentState = IDLE;


// ---------------- RSSI / Printing ----------------
static int8_t PRINT_RSSI_THRESH = -30;
static volatile int8_t  last_rssi_dbm = -127;
static volatile bool    rssi_ready    = false;

// ---------------- Sweep Bookkeeping ------------
static uint32_t ch_hits[(MAX_CH - MIN_CH + 1)];
static uint8_t  best_ch_found = 50; // Default start channel

// ---------------- Radio Parameters ----------------
static bool     whitening_enabled = false;
static uint32_t current_mode      = RADIO_MODE_MODE_Nrf_2Mbit;
static uint8_t  BALEN             = 1;  // 1..4 (Addrs len = BALEN+1)
static uint8_t  LFLEN             = 0;  // 0..8 bits
static uint8_t  S1LEN             = 0;  // 0..7 bits
static uint8_t  STATLEN           = 32; // 0 = Dynamic
static uint8_t  current_crc_len   = 0;  // 0=Off, 1=8bit, 2=16bit
static bool     header_parse_enabled = false;
static bool     locked = false;

// Advanced Params
static bool     payload_endian_little = false; // Big (BLE) default
static uint8_t  crc_param_profile     = 0;     // 0=Default, 1=Kermit, 2=Modbus, 3=ARC
static bool     crc_skip_addr         = false;
static int8_t   bit_shift_amount      = 0;     // -7 to +7
static bool     clean_output_mode     = false; // Toggle for clean payload printing
static uint8_t  current_plen_mode = 0; // 0=8bit, 1=16bit, 2=32bit, 3=LongRange
static int8_t   focused_pipe_idx  = -1; // -1 = ALL, 0-7 = Specific

// ---------------- Address Preset System ----------------
struct AddressPreset {
    const char* name;
    bool raw_mode;
    uint8_t base0[4];
    uint8_t base1[4];
    uint8_t prefixes[8];
};

// --- Preset 0 ---
static const AddressPreset PRESET_LOGITACKER = {
    "LOGI", false, 
    {0xA8, 0xA8, 0xA8, 0xA8}, 
    {0xAA, 0xAA, 0xAA, 0xAA}, 
    {0xAA, 0x1F, 0x9F, 0xA8, 0xAF, 0xA9, 0x8F, 0xAA}
};

// --- Preset 1 ---
static const AddressPreset PRESET_PURE = {
    "PURE PREAMBLE", false, 
    {0x55, 0x55, 0x55, 0x55}, 
    {0xAA, 0xAA, 0xAA, 0xAA}, 
    {0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA} 
};

// --- Preset 2 ---
static const AddressPreset PRESET_CALC = {
    "CALC", false, 
    {0x5A, 0x5A, 0x5A, 0x5A}, 
    {0xA5, 0xA5, 0xA5, 0xA5}, 
    {0x2A, 0x4A, 0x52, 0x54, 0xAB, 0xAD, 0xB5, 0xD5} 
};

// --- Preset 3 ---
static const AddressPreset PRESET_ZERO_BASE = {
    "ZERO+BASE", true, 
    {0x00, 0x00, 0x00, 0x00}, 
    {0x00, 0x00, 0x00, 0x00}, 
    {0xAA, 0x55, 0xAB, 0x56, 0xA8, 0x54, 0x0F, 0xF0} 
};

static const AddressPreset* PRESETS[] = { &PRESET_LOGITACKER, &PRESET_PURE, &PRESET_CALC, &PRESET_ZERO_BASE };
static const uint8_t NUM_PRESETS = 4;
static uint8_t current_preset_idx = 0;

// Flag to switch between "Preset Mode"  and "Manual Mode" 
static bool use_preset_mode = false; 

// ---------------- Address Config (Manual) ----------------
static bool     have_prefix = false;
static uint8_t  discovered_prefix = 0xAA;
static uint8_t  discovered_base[4] = {0};
static uint8_t  discovered_count = 0;

// ---------------- Discovery Logic Structs (NEW) ----------------
#define DISCOVERY_MAX_CANDIDATES   100
#define DISCOVERY_CYCLE_MS         400 
#define DISCOVERY_RAW_LEN          64  
#define SEARCH_LOCK_THRESHOLD      10
#define FAST_CYCLE_MS              75 

struct Candidate {
  uint8_t addr[5];
  uint8_t hits;
  uint32_t last_seen;
  bool active;
};

struct DiscoveryStats {
  uint32_t packets_captured;
  uint32_t calculations_performed;
  uint32_t crc_matches;
  uint32_t start_time;
};

struct CRCProfile {
    uint16_t poly;
    uint16_t init;
    const char* name;
};

// Common 2.4GHz CRC Standards
static const CRCProfile CRC_PROFILES[] = {
    {0x1021, 0xFFFF, "nRF"},    // Standard nRF24L01+
    {0x1021, 0x0000, "Kerm"},   // Kermit
    {0x8005, 0xFFFF, "Mod"},    // Modbus
    {0x8005, 0x0000, "ARC"}     // ARC
};

static Candidate candidates[DISCOVERY_MAX_CANDIDATES];
static DiscoveryStats d_stats;
static bool abort_discovery = false;


// ---------------- Record/Replay State ----------------
#define MAX_RECORDED_PACKETS 50
#define MAX_RECORDED_PAYLOAD 64

typedef struct {
  uint8_t len;
  uint8_t data[MAX_RECORDED_PAYLOAD];
  uint32_t timestamp_ms;
} RecordedPacket;

static RecordedPacket recorded_packets[MAX_RECORDED_PACKETS];
static uint16_t recorded_packet_count = 0;
static bool is_recording = false;


// =============================================================================
//                     SCHEDULER / PACKET QUEUE (NEW)
// =============================================================================
#define RX_QUEUE_SIZE 32 // Buffer up to 32 packets

typedef struct {
  uint8_t  len;
  uint8_t  data[64]; // Raw buffer copy
  int8_t   rssi;
  uint8_t  pipe;
  uint32_t timestamp;
  bool     crc_ok;
} QueueItem;

static QueueItem rx_queue[RX_QUEUE_SIZE];
static volatile uint8_t queue_head = 0; // Write pos
static volatile uint8_t queue_tail = 0; // Read pos

static bool is_queue_empty() {
  return (queue_head == queue_tail);
}

static bool is_queue_full() {
  return ((queue_head + 1) % RX_QUEUE_SIZE) == queue_tail;
}

static void push_to_queue(uint8_t* raw_data, uint8_t len, int8_t rssi, uint8_t pipe, bool crc) {
  if (is_queue_full()) return; // Drop packet if CPU is too slow
  
  rx_queue[queue_head].len = len;
  memcpy(rx_queue[queue_head].data, raw_data, len);
  rx_queue[queue_head].rssi = rssi;
  rx_queue[queue_head].pipe = pipe;
  rx_queue[queue_head].crc_ok = crc;
  rx_queue[queue_head].timestamp = millis();
  
  queue_head = (queue_head + 1) % RX_QUEUE_SIZE;
}


// =============================================================================
//                                   HELPERS
// =============================================================================

static void print_byte(uint8_t b) {
    if (b < 0x10) Serial.print('0');
    Serial.print(b, HEX);
}

static void print_hex(const uint8_t* b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    print_byte(b[i]);
    Serial.print(' ');
  }
  Serial.println();
}

static inline void print_ts() {
  Serial.print('['); Serial.print(millis()); Serial.print(" ms] ");
}

// --- Bit Swap / Addr Conv ---
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

// --- Bit Shift ---
static void apply_bit_shift(uint8_t* buffer, size_t len, int8_t shift_bits) {
  if (len == 0 || shift_bits == 0) return;
  int8_t shift = shift_bits % 8;
  if (shift == 0) return;

  if (shift > 0) { // Shift RIGHT
    int8_t rshift = shift;
    uint8_t carry = 0;
    for (int i = (int)len - 1; i >= 0; i--) { 
      uint8_t next_carry = (buffer[i] << (8 - rshift));
      buffer[i] = (buffer[i] >> rshift) | carry;
      carry = next_carry;
    }
  } else { // Shift LEFT
    int8_t lshift = -shift;
    uint8_t carry = 0;
    for (size_t i = 0; i < len; i++) {
      uint8_t next_carry = (buffer[i] >> (8 - lshift));
      buffer[i] = (buffer[i] << lshift) | carry;
      carry = next_carry;
    }
  }
}

// --- Software CRC Implementation (For Discovery) ---
uint16_t soft_crc16(const uint8_t *data, size_t len, uint16_t poly, uint16_t init) {
    uint16_t crc = init;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) crc = (crc << 1) ^ poly;
            else              crc <<= 1;
        }
    }
    return crc;
}

void process_scheduler() {
  // Process as many packets as available
  while (!is_queue_empty()) {
    
    // Pop from queue
    QueueItem* item = &rx_queue[queue_tail];
    
    // --- LOGIC FROM OLD POLL_RADIO_EVENTS GOES HERE ---
    
    if (item->rssi >= PRINT_RSSI_THRESH) {
      
      // 1. Calculate offsets based on current LFLEN/S1LEN settings
      // (We need to re-cast the raw bytes from the queue back to struct logic)
      esb_rx_t* p_pkt = (esb_rx_t*)item->data;
      
      uint8_t* payload_start_ptr;
      size_t   payload_actual_len;
      
      if (LFLEN > 0) {
         uint8_t lmask = (LFLEN >= 8) ? 0xFFu : (uint8_t)((1u << LFLEN) - 1u);
         payload_actual_len = (size_t)(p_pkt->LENGTH & lmask);
         if (S1LEN > 0) payload_start_ptr = p_pkt->payload;
         else           payload_start_ptr = &p_pkt->S1;
      } else {
         payload_start_ptr = (uint8_t*)&p_pkt->LENGTH;
         payload_actual_len = (STATLEN == 0) ? 32 : STATLEN;
      }
      
      // Safety clamps
      if (payload_actual_len > 60) payload_actual_len = 60;

      // 2. Recording Logic
      if (is_recording && recorded_packet_count < MAX_RECORDED_PACKETS && item->crc_ok) {
         size_t pdu_total_len = payload_actual_len;
         if (LFLEN > 0) pdu_total_len += (1 + (S1LEN > 0 ? 1 : 0)); // Add header bytes
         
         if (pdu_total_len > 0 && pdu_total_len <= MAX_RECORDED_PAYLOAD) {
            recorded_packets[recorded_packet_count].len = (uint8_t)pdu_total_len;
            memcpy(recorded_packets[recorded_packet_count].data, item->data, pdu_total_len);
            recorded_packets[recorded_packet_count].timestamp_ms = item->timestamp;
            recorded_packet_count++;
            digitalWrite(LED_PIN, HIGH); delay(1); digitalWrite(LED_PIN, LOW);
         }
      }

      // 3. Printing Logic
      // Reconstruct metadata print
      if (!clean_output_mode) {
          Serial.print(F("[")); Serial.print(item->timestamp); Serial.print(F("] "));
          Serial.print(F("Ch ")); Serial.print(best_ch_found);
          Serial.print(F(" pipe=")); Serial.print(item->pipe);
          Serial.print(F(" RSSI=")); Serial.print(item->rssi); Serial.print(F("dBm"));
          if (current_crc_len > 0) Serial.print(item->crc_ok ? " CRC=OK " : " CRC=BAD ");
          else Serial.print(F(" -> "));
      }

      if (item->crc_ok) {
          // Header parse print
          if (!clean_output_mode && header_parse_enabled && LFLEN > 0) {
             uint8_t lmask = (LFLEN >= 8) ? 0xFFu : (uint8_t)((1u << LFLEN) - 1u);
             Serial.print(F("LEN=")); Serial.print(p_pkt->LENGTH & lmask);
             if (S1LEN > 0) {
               Serial.print(F(" S1=0x")); Serial.print(p_pkt->S1, HEX);
             }
             Serial.print(F(" -> "));
          }

          // Payload print (with Bit Shift support)
          if (bit_shift_amount != 0) {
             uint8_t shifted_payload[64];
             memcpy(shifted_payload, payload_start_ptr, payload_actual_len);
             apply_bit_shift(shifted_payload, payload_actual_len, bit_shift_amount);
             print_hex(shifted_payload, payload_actual_len);
          } else {
             print_hex(payload_start_ptr, payload_actual_len);
          }
      } else {
          if (!clean_output_mode) Serial.println();
      }
    }

    // Advance Tail
    queue_tail = (queue_tail + 1) % RX_QUEUE_SIZE;
  }
}

// =============================================================================
//                             UI / PRINT FUNCTIONS
// =============================================================================

void print_params() {
  Serial.println(F("\n--- Current Settings ---"));
  
  // 1. System State
  Serial.print(F("State: "));
  switch (currentState) {
    case IDLE: Serial.println(F("IDLE")); break;
    case SWEEPING: Serial.println(F("SWEEPING")); break;
    case ANALYZING: Serial.println(F("ANALYZING")); break;
    case LISTENING: Serial.println(F("LISTENING")); break;
  }

  // 2. RF Physical Layer
  Serial.print(F("Locked Channel: ")); Serial.println(best_ch_found);
  Serial.print(F("Data Rate: ")); Serial.println((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2M" : "1M");
  Serial.print(F("Whitening: ")); Serial.println(whitening_enabled ? "ENABLED" : "DISABLED");
  
  Serial.print(F("PLEN Mode: ")); Serial.print(current_plen_mode);
  switch(current_plen_mode) {
      case 0: Serial.println(F(" (8-bit)")); break;
      case 1: Serial.println(F(" (16-bit)")); break;
      case 2: Serial.println(F(" (32-bit Zero)")); break;
      case 3: Serial.println(F(" (Long Range)")); break;
  }
  
  // 3. Address / Pipe Config
  Serial.print(F("Mode: ")); Serial.println(use_preset_mode ? "PRESET MODE" : "MANUAL MODE");
  if (use_preset_mode) {
      Serial.print(F("Preset: [")); Serial.print(current_preset_idx); Serial.print(F("] ")); Serial.print(PRESETS[current_preset_idx]->name);
      Serial.print(F(" | Focus: "));
      if (focused_pipe_idx == -1) Serial.println(F("ALL Pipes"));
      else { Serial.print(F("Pipe ")); Serial.println(focused_pipe_idx); }
  } else {
      Serial.print (F("Manual Prefix: "));
      if (have_prefix) { Serial.print(F("0x")); Serial.print(discovered_prefix, HEX); }
      else { Serial.print(F("0xAA (default)")); }
      Serial.println(F(" on pipe0"));
      
      Serial.print(F("Base bytes (LSB->MSB): "));
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

  // 5. CRC
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

  // 6. Tools
  Serial.print(F("Bit Shift: ")); Serial.println(bit_shift_amount);
  Serial.print(F("Output Format: ")); Serial.println(clean_output_mode ? "CLEAN (Payload Only)" : "VERBOSE");
  Serial.print(F("Recorded packets: ")); Serial.print(recorded_packet_count);
  Serial.print(F(" / ")); Serial.println(MAX_RECORDED_PACKETS);
  Serial.println(F("------------------------\n"));
}

void print_help() {
  Serial.println(F("\nKeys:"));

  // ---- General ----
  Serial.println(F("  h   : help"));
  Serial.println(F("  P   : print current parameter settings"));
  Serial.println(F("  S   : run a single sweep"));
  Serial.println(F("  T   : set exact RSSI threshold in dBm (e.g., -55) then Enter"));
  Serial.println(F("  [   : raise RSSI threshold by +5 dB"));
  Serial.println(F("  ]   : lower RSSI threshold by -5 dB"));

  // ---- Pipes ----
  Serial.println(F("  ---------------------------- Pipes ----------------------------"));
  Serial.println(F("  A   : listen on ALL pipes"));
  Serial.println(F("  0-7 : focus on specific pipe #"));

  // ---- Discovery ----
  Serial.println(F("  ----------------------- Address Config ------------------------"));
  Serial.println(F("  M   : set manual address (e.g., AA 12 34)"));
  Serial.println(F("  n   : cycle address presets (promiscuous addresses)"));
  Serial.println(F("  X   : START SMART ADDRESS DISCOVERY (Active)"));
  Serial.println(F("  Z   : clear manual address (Reset to default 0xAA)"));

  // ---- Record / Fire ----
  Serial.println(F("  ----------------------- Record / Fire ------------------------"));
  Serial.println(F("  R   : toggle packet recording (LISTENING only)"));
  Serial.println(F("  f   : fire (transmit) recorded packets"));

  // ---- Sniffer config ----
  Serial.println(F("  ---------------------- Sniffer (LISTENING) -------------------"));
  Serial.println(F("  W   : toggle whitening"));
  Serial.println(F("  D   : toggle data rate (1M/2M)"));
  Serial.println(F("  b   : cycle BALEN (1..4)"));
  Serial.println(F("  l   : cycle LFLEN (0..8)"));
  Serial.println(F("  s   : cycle S1LEN (0..7)"));
  Serial.println(F("  t   : cycle STATLEN (0/6/8/16/24/32/64)"));
  Serial.println(F("  K   : set exact STATLEN (0-255) then Enter"));
  Serial.println(F("  C   : cycle CRC (Off/1B/2B)"));
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

// --- Print Summary of Candidates ---
void print_discovery_summary() {
  // Create a temporary array of pointers to sort without messing up the main array order
  Candidate* sorted_ptrs[DISCOVERY_MAX_CANDIDATES];
  int active_count = 0;

  for (int i = 0; i < DISCOVERY_MAX_CANDIDATES; i++) {
    if (candidates[i].active) {
      sorted_ptrs[active_count++] = &candidates[i];
    }
  }

  // Simple Bubble Sort (Highest hits first)
  for (int i = 0; i < active_count - 1; i++) {
    for (int j = 0; j < active_count - i - 1; j++) {
      if (sorted_ptrs[j]->hits < sorted_ptrs[j + 1]->hits) {
        Candidate* temp = sorted_ptrs[j];
        sorted_ptrs[j] = sorted_ptrs[j + 1];
        sorted_ptrs[j + 1] = temp;
      }
    }
  }

  Serial.println(F("\n\n--- DISCOVERY CANDIDATE SUMMARY ---"));
  Serial.println(F("Hits  | Last Seen | Address"));
  Serial.println(F("-----------------------------------"));

  if (active_count == 0) {
    Serial.println(F("(No candidates found yet)"));
  } else {
    uint32_t now = millis();
    for (int i = 0; i < active_count; i++) {
      Candidate* c = sorted_ptrs[i];
      Serial.print(c->hits); 
      if(c->hits < 10) Serial.print("     | -");
      else if(c->hits < 100) Serial.print("    | -");
      else Serial.print("   | -");
      
      Serial.print(now - c->last_seen); Serial.print(F("ms   | "));
      print_hex(c->addr, 5);
    }
  }
  Serial.println(F("-----------------------------------\n"));
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
  // PCNF0: Includes PLEN + LFLEN/S1LEN
  NRF_RADIO->PCNF0 =
    (0 << RADIO_PCNF0_S0LEN_Pos) |
    (LFLEN << RADIO_PCNF0_LFLEN_Pos) |
    (S1LEN << RADIO_PCNF0_S1LEN_Pos) |
    (current_plen_mode << RADIO_PCNF0_PLEN_Pos);

  // PCNF1: Includes Whitening, Endianness, BALEN, STATLEN, MaxPayload
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

// Master Radio Configuration
void radio_base_config() {
  NRF_CLOCK->EVENTS_HFCLKSTARTED = 0;
  NRF_CLOCK->TASKS_HFCLKSTART = 1;
  while (NRF_CLOCK->EVENTS_HFCLKSTARTED == 0) {}

  // FORCE RESET PCNF to clear weird states
  NRF_RADIO->PCNF0 = 0;
  NRF_RADIO->PCNF1 = 0;

  NRF_RADIO->MODE = current_mode << RADIO_MODE_MODE_Pos;
  apply_pcnf0_pcnf1();

  // --- ADDRESS LOGIC ---
  if (use_preset_mode) {
      //Load from Preset Array
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

      // Pipe Focus Logic (Hardware filtering)
      if (focused_pipe_idx == -1) {
          NRF_RADIO->RXADDRESSES = 0xFF; // Listen to pipes 0-7
      } else {
          NRF_RADIO->RXADDRESSES = (1 << focused_pipe_idx);
      }

  } else {
      // Manual Address Mode
      if (have_prefix) {
        NRF_RADIO->PREFIX0 = discovered_prefix;
        NRF_RADIO->PREFIX1 = 0;
        NRF_RADIO->RXADDRESSES = (1 << 0); // Enable only pipe 0

        uint32_t final_base = 0;
        for(uint8_t i=0; i<discovered_count; i++) {
          final_base |= ((uint32_t)discovered_base[i]) << (8*i);
        }
        NRF_RADIO->BASE0 = final_base;
        NRF_RADIO->BASE1 = 0x00000000UL;
      } else {
        // Default sniff settings (0xAA default)
        NRF_RADIO->BASE0    = 0x00000000UL;
        NRF_RADIO->BASE1    = 0x00000000UL;
        NRF_RADIO->PREFIX0  = 0xAA; 
        NRF_RADIO->PREFIX1  = 0x00000000UL;
        NRF_RADIO->RXADDRESSES = (1 << 0); 
      }
  }

  // --- CRC CONFIGURATION ---
  switch (crc_param_profile) {
    case 0: // Default: nRF24, CCITT-FALSE
      NRF_RADIO->CRCPOLY = 0x00001021UL; NRF_RADIO->CRCINIT = 0x0000FFFFUL; break;
    case 1: // Kermit
      NRF_RADIO->CRCPOLY = 0x00001021UL; NRF_RADIO->CRCINIT = 0x00000000UL; break;
    case 2: // Modbus / CRC-16-IBM
      NRF_RADIO->CRCPOLY = 0x00008005UL; NRF_RADIO->CRCINIT = 0x0000FFFFUL; break;
    case 3: // ARC / CRC-16
      NRF_RADIO->CRCPOLY = 0x00008005UL; NRF_RADIO->CRCINIT = 0x00000000UL; break;
  }

  uint32_t crc_val = RADIO_CRCCNF_LEN_Disabled;
  if (current_crc_len == 1) crc_val = RADIO_CRCCNF_LEN_One;
  else if (current_crc_len == 2) crc_val = RADIO_CRCCNF_LEN_Two;

  uint32_t crc_conf_val = (crc_val << RADIO_CRCCNF_LEN_Pos);
  if (crc_skip_addr) {
    crc_conf_val |= (RADIO_CRCCNF_SKIPADDR_Skip << RADIO_CRCCNF_SKIPADDR_Pos);
  }
  NRF_RADIO->CRCCNF = crc_conf_val;

  // Continuous RX shorts
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

// ---------------- Prefix helpers ----------------
static void restore_single_pipe_prefix(uint8_t prefix = 0xAA) {
  NRF_RADIO->PREFIX0 = prefix;
  NRF_RADIO->PREFIX1 = 0;
  NRF_RADIO->RXADDRESSES = (1 << 0);
  NRF_RADIO->BASE0 = 0x00000000UL;
  NRF_RADIO->BASE1 = 0x00000000UL;
}

// =============================================================================
//                         nRF24 TARGET TRANSMITTER
// =============================================================================

static void configure_target_transmitter() {
  Serial.println("Configuring nRF24 as TARGET TRANSMITTER...");
  if (!radio.begin()) {
    Serial.println("nRF24L01+ (Sender) not responding. Check wiring.");
    return;
  }
  radio.setDataRate(RF24_1MBPS);
  radio.setChannel(TARGET_RF_CHANNEL);
  radio.setAddressWidth(5);
  radio.openWritingPipe(target_rf_address);
  radio.setPALevel(RF24_PA_MAX);
  radio.setCRCLength(RF24_CRC_16);
  radio.setAutoAck(false);
  radio.setRetries(0, 0);
  radio.setPayloadSize(TARGET_RADIO_PAYLOAD_SIZE);
  radio.stopListening();
  Serial.println("nRF24 TARGET configured. Will start transmitting in loop.");
}

static unsigned long last_tx_time = 0;
static uint8_t tx_counter = 0;

static void run_target_transmitter() {
  // Send a packet every ~1000ms (non-blocking)
  if (millis() - last_tx_time < 1000) {
    return; // Not time yet
  }
  last_tx_time = millis();

  // Build TX payload
  char tx[TARGET_RADIO_PAYLOAD_SIZE] = {0};
  strcpy(tx, "Hello Sniffer!");
  tx[14] = tx_counter++; // Put counter at the end

  radio.write(&tx, TARGET_RADIO_PAYLOAD_SIZE);
}

// =============================================================================
//                            EVENT PROCESSING (POLLING)
// =============================================================================

void poll_radio_events() {
  // 1. Handle Address Event (Start RSSI)
  if (NRF_RADIO->EVENTS_ADDRESS) {
    NRF_RADIO->EVENTS_ADDRESS = 0;
    NRF_RADIO->EVENTS_RSSIEND = 0;
    NRF_RADIO->TASKS_RSSISTART = 1; // Start RSSI measurement
  }

  // 2. Handle RSSI End
  if (NRF_RADIO->EVENTS_RSSIEND) {
    NRF_RADIO->EVENTS_RSSIEND = 0;
    last_rssi_dbm = -(int8_t)NRF_RADIO->RSSISAMPLE;
    rssi_ready = true;
  }

  // 3. Handle Packet End (The Critical Part)
  if (NRF_RADIO->EVENTS_END) {
    NRF_RADIO->EVENTS_END = 0;

    // Snapshot critical data
    int8_t rssi = rssi_ready ? last_rssi_dbm : -127;
    bool crc_ok = (current_crc_len == 0) ? true : (NRF_RADIO->CRCSTATUS == 1);
    uint8_t pipe = NRF_RADIO->RXMATCH & 0x07;

    // --- FAST COPY TO QUEUE ---
    // We copy the max raw discovery length (64) to be safe, 
    // or calculate based on LFLEN if we trust the header.
    // For stability/discovery, we grab everything.
    push_to_queue((uint8_t*)&esb_rx_buf, 64, rssi, pipe, crc_ok);

    // --- IMMEDIATE RADIO RESTART ---
    // Don't wait for printing. Restart RX now.
    NRF_RADIO->TASKS_RXEN = 1; 

    // Clear flags for next packet
    rssi_ready = false;
    last_rssi_dbm = -127;
  }
}
// =============================================================================
//                                  SWEEPING
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
        bool crc_ok = (current_crc_len == 0) ? true : (NRF_RADIO->CRCSTATUS == 1);
        if (rssi_ready && last_rssi_dbm >= PRINT_RSSI_THRESH && crc_ok) {
          local_hits++;
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
//                             AUTO ADDRESS DISCOVERY
// =============================================================================


void register_candidate(uint8_t* raw_addr_bytes) {
    uint32_t now = millis();

    // 1. Check if exists (Update hits)
    for (int i = 0; i < DISCOVERY_MAX_CANDIDATES; i++) {
        if (candidates[i].active) {
            if (memcmp(candidates[i].addr, raw_addr_bytes, 5) == 0) {
                candidates[i].hits++;
                candidates[i].last_seen = now;
                d_stats.crc_matches++;
                return; 
            }
        }
    }

    // 2. Check for empty slot (Add new)
    for (int i = 0; i < DISCOVERY_MAX_CANDIDATES; i++) {
        if (!candidates[i].active) {
            memcpy(candidates[i].addr, raw_addr_bytes, 5);
            candidates[i].hits = 1;
            candidates[i].last_seen = now;
            candidates[i].active = true;
            d_stats.crc_matches++;
            
            Serial.println(); 
            Serial.print(F("[+] New Candidate: "));
            print_hex(candidates[i].addr, 5);
            return;
        }
    }

    // 3. FIX: Eviction Policy (List is full)
    // Find the oldest candidate and overwrite it
    int oldest_idx = -1;
    uint32_t oldest_time = 0xFFFFFFFF;

    for (int i = 0; i < DISCOVERY_MAX_CANDIDATES; i++) {
        if (candidates[i].active && candidates[i].last_seen < oldest_time) {
            oldest_time = candidates[i].last_seen;
            oldest_idx = i;
        }
    }

    if (oldest_idx != -1) {
        memcpy(candidates[oldest_idx].addr, raw_addr_bytes, 5);
        candidates[oldest_idx].hits = 1;
        candidates[oldest_idx].last_seen = now;
        candidates[oldest_idx].active = true;
        d_stats.crc_matches++;

        Serial.println();
        Serial.print(F("[!] List full. Evicting old candidate for: "));
        print_hex(candidates[oldest_idx].addr, 5);
    }
}


// --- Helper: Validate Address Entropy (Prevent locking on AA 00 00 00 00) ---
bool is_valid_candidate(uint8_t* addr) {
    // Reject all zeros or all FFs (common in noise)
    int zeros = 0;
    int ffs = 0;
    for(int i=1; i<5; i++) { // Skip prefix, check base
        if (addr[i] == 0x00) zeros++;
        if (addr[i] == 0xFF) ffs++;
    }
    if (zeros >= 3) return false; // Reject AA 00 00 00 01
    if (ffs >= 3) return false;   // Reject AA FF FF FF FE
    
    return true;
}

void analyze_raw_packet(uint8_t* raw_buf) {
    // We use a slightly larger buffer for the work area to handle shifts safely
    uint8_t work_buf[DISCOVERY_RAW_LEN + 2]; 

    // 1. Bit Shift Loop (-7 to +7)
    for (int8_t shift = -7; shift <= 7; shift++) {
        
        // Reset work buffer from raw
        memcpy(work_buf, raw_buf, DISCOVERY_RAW_LEN); 
        // Apply the shift
        apply_bit_shift(work_buf, DISCOVERY_RAW_LEN, shift);

        // [FIX 1] Logic Fix: One Packet Per Shift
        // If we find a valid packet at this specific bit-shift, it is physically 
        // impossible for a longer packet to exist starting at the same bit.
        bool match_found_in_shift = false;

        // 2. Sliding Window Loop (Payload Length 5 to 32)
        for (uint8_t len = 5; len <= 32; len++) {
            
            // [FIX 1] Optimization: Stop scanning lengths if we already locked a packet here
            if (match_found_in_shift) break;

            // Extract the "CRC" from the air (at end of hypothetical packet)
            uint16_t crc_air = (work_buf[len] << 8) | work_buf[len+1];

            // [FIX 2] Filter Fix: Zero-CRC Trap
            // In blind sniffing, 0x0000 is 99.9% likely to be an empty buffer artifact.
            // Rejecting this prevents the "Null Slide" bug.
            if (crc_air == 0x0000) continue;

            // 3. CRC Profile Loop
            for (uint8_t c_idx = 0; c_idx < 4; c_idx++) {
                d_stats.calculations_performed++;
                
                uint16_t crc_calc = soft_crc16(work_buf, len, CRC_PROFILES[c_idx].poly, CRC_PROFILES[c_idx].init);

                if (crc_calc == crc_air) {
                    // CRC MATCH FOUND!
                    
                    // Construct candidate from the bytes strictly inside the buffer
                    uint8_t discovered_addr[5];
                    discovered_addr[0] = work_buf[0];   
                    discovered_addr[1] = work_buf[1];   
                    discovered_addr[2] = work_buf[2];   
                    discovered_addr[3] = work_buf[3];   
                    discovered_addr[4] = work_buf[4];   
                    
                    // VALIDATION CHECK
                    if (is_valid_candidate(discovered_addr)) {
                        register_candidate(discovered_addr);
                        
                        // [FIX 1] Flag that we found the packet for this shift
                        match_found_in_shift = true;

                        Serial.println(F("\n   -> VALID PACKET FOUND:"));
                        Serial.print(F("      [Meta] Shift: ")); Serial.print(shift);
                        Serial.print(F(" | Len: ")); Serial.print(len);
                        Serial.print(F(" | CRC: ")); Serial.print(crc_calc, HEX);
                        Serial.print(F(" (")); Serial.print(CRC_PROFILES[c_idx].name); Serial.println(F(")"));
                        
                        Serial.print(F("      [Addr] ")); print_hex(discovered_addr, 5);
                        
                        // Calculate Payload size (Len - Address(5))
                        int payload_sz = len - 5;
                        Serial.print(F("      [Payl] "));
                        if (payload_sz > 0) {
                            print_hex(&work_buf[5], payload_sz);
                        } else {
                            Serial.println(F("(Empty)"));
                        }

                        // --- Print Raw and Shifted Buffers (Preserved) ---
                        Serial.print(F("      [Raw ] ")); 
                        print_hex(raw_buf, 32); 

                        Serial.print(F("      [Shft] ")); 
                        print_hex(work_buf, 32);
                        
                        Serial.println(F("   --------------------------------"));
                    }
                }
            }
        }
    }
}


// --- Main Discovery Routine (Optimized) ---
void auto_address_discovery() {
  Serial.println(F("\n========================================"));
  Serial.println(F("   SMART ADDRESS DISCOVERY (Scheduler Mode)"));
  Serial.println(F("========================================"));
  Serial.println(F(" [s] -> Print Summary of top contenders"));
  Serial.println(F(" [x] -> Stop / Abort"));
  Serial.print(F("Filter: Analyzing only signals >= ")); 
  Serial.print(PRINT_RSSI_THRESH); Serial.println(F(" dBm"));
  
  Serial.print(F("Fixed Data Rate: ")); 
  Serial.println((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2M" : "1M");

  // --- 1. SAVE STATE ---
  bool saved_endian = payload_endian_little;
  uint8_t saved_crc_len = current_crc_len;
  uint8_t saved_statlen = STATLEN;
  uint8_t saved_balen   = BALEN;

  memset(&d_stats, 0, sizeof(d_stats));
  memset(candidates, 0, sizeof(candidates));
  d_stats.start_time = millis();
  abort_discovery = false;

  // Clear Queue before starting
  queue_head = 0; queue_tail = 0;

  // --- 2. RAW CAPTURE SETUP ---
  radio_disable();
  NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | 
                      RADIO_SHORTS_END_DISABLE_Msk | 
                      RADIO_SHORTS_ADDRESS_RSSISTART_Msk; 
  NRF_RADIO->CRCCNF = 0; // Disable HW CRC
  
  int config_step = 0;
  unsigned long last_config_change = 0;
  last_config_change = millis() - FAST_CYCLE_MS - 1; 
  
  while (!abort_discovery) {
      
      // --- User Input Handling (MODIFIED) ---
      if (Serial.available()) {
          char c = Serial.read(); 
          
          if (c == 's' || c == 'S') {
             // Show summary but continue
             print_discovery_summary();
          } 
          else {
            // Any other key triggers abort
            abort_discovery = true;
            // Restore
            payload_endian_little = saved_endian;
            current_crc_len = saved_crc_len;
            STATLEN = saved_statlen;
            BALEN = saved_balen;
            Serial.println(F("\n>>> ABORTED. Restoring Original Settings."));
            break;
          }
      }

      // --- Configuration Rotation ---
      if (millis() - last_config_change > FAST_CYCLE_MS) {
          last_config_change = millis();
          
          bool endian_be = (config_step % 2) != 0;        
          uint8_t p_idx  = (config_step / 2) % NUM_PRESETS; 
          config_step++; 

          radio_disable();
          NRF_RADIO->MODE = current_mode << RADIO_MODE_MODE_Pos;
          
          const AddressPreset* p = PRESETS[p_idx];
          NRF_RADIO->BASE0 = addr_conv(p->base0, p->raw_mode);
          NRF_RADIO->BASE1 = addr_conv(p->base1, p->raw_mode);
          
          if (p->raw_mode) {
               NRF_RADIO->PREFIX0 = (p->prefixes[3] << 24) | (p->prefixes[2] << 16) | (p->prefixes[1] << 8) | p->prefixes[0];
          } else {
               NRF_RADIO->PREFIX0 = bytewise_bit_swap(&p->prefixes[0]); 
          }
          NRF_RADIO->RXADDRESSES = 0xFF; 
          
          uint32_t endian_bit = endian_be ? RADIO_PCNF1_ENDIAN_Big : RADIO_PCNF1_ENDIAN_Little;
          NRF_RADIO->PCNF0 = 0; 
          
          // BALEN = 1 (Promiscuous for discovery)
          NRF_RADIO->PCNF1 = (DISCOVERY_RAW_LEN << RADIO_PCNF1_MAXLEN_Pos) | 
                             (DISCOVERY_RAW_LEN << RADIO_PCNF1_STATLEN_Pos) |
                             (endian_bit << RADIO_PCNF1_ENDIAN_Pos) |
                             (1 << RADIO_PCNF1_BALEN_Pos) |  
                             (RADIO_PCNF1_WHITEEN_Disabled << RADIO_PCNF1_WHITEEN_Pos);
          
          set_channel(best_ch_found);
          
          if (config_step % 16 == 0) { // Slower status update to reduce spam
              Serial.print(F("\r[SCAN] ")); 
              Serial.print((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? F("2MB") : F("1MB"));
              Serial.print(endian_be ? F("|BE") : F("|LE"));
              Serial.print(F(" | Pkts:")); Serial.print(d_stats.packets_captured);
              Serial.print(F(" | Calcs:")); Serial.print(d_stats.calculations_performed);
          }
      }

      // --- 3. CAPTURE (Producer) ---
      // We poll events, which pushes to RX_QUEUE
      poll_radio_events();

      // --- 4. ANALYZE (Consumer) ---
      // Process entire queue while we wait for next config cycle or next packet
      while (!is_queue_empty()) {
          QueueItem* item = &rx_queue[queue_tail];

          // Only analyze if strong signal
          if (item->rssi >= PRINT_RSSI_THRESH) {
              d_stats.packets_captured++;
              analyze_raw_packet(item->data); // Heavy math happens here
          }

          queue_tail = (queue_tail + 1) % RX_QUEUE_SIZE;

          // Check Locks inside consumer loop
          for(int i=0; i<DISCOVERY_MAX_CANDIDATES; i++) {
              if (candidates[i].active && candidates[i].hits >= SEARCH_LOCK_THRESHOLD) {
                  Serial.println(F("\n\n>>> LOCK ACQUIRED! <<<"));
                  Serial.print(F("Address: "));
                  print_hex(candidates[i].addr, 5);
                  Serial.print(F("Settings: "));
                  Serial.print((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2M" : "1M");
                  
                  bool found_be = ((config_step - 1) % 2) != 0;
                  Serial.println(found_be ? " BE" : " LE");

                  discovered_count = 4; 
                  BALEN = 4; 
                  discovered_prefix = candidates[i].addr[0];
                  memcpy(discovered_base, &candidates[i].addr[1], 4);
                  have_prefix = true;
                  use_preset_mode = false;
                  
                  payload_endian_little = !found_be;
                  current_crc_len = 2; 
                  STATLEN = 32; 
                  
                  abort_discovery = true;
                  break;
              }
          }
          if (abort_discovery) break;
      }
  }
  
  Serial.println(F("\nDiscovery End. Reapplying Sniffer Config..."));
  configure_radio_for_state(LISTENING);
  currentState = LISTENING;
}
// =============================================================================
//                            ADDRESS LOGIC (MANUAL CLEANUP)
// =============================================================================

void clear_manual_address() {
  use_preset_mode = false; // Force manual mode
  have_prefix = false;
  discovered_prefix = 0xAA;
  memset(discovered_base, 0, sizeof(discovered_base));
  discovered_count = 0;
  restore_single_pipe_prefix(0xAA);
  BALEN = 1; 
  apply_pcnf0_pcnf1();
  set_channel(best_ch_found);
  Serial.println(">>> Manual address cleared. Defaulting to 0xAA (single pipe).");
}


// =============================================================================
//                              REPLAY (FIRE)
// =============================================================================

void fire_recorded_packets() {
  if (recorded_packet_count == 0) { Serial.println("No packets to fire. Press 'R' to start/stop recording first."); return; }
  
  radio_disable();
  radio_base_config(); // Configure TX with same params as RX
  NRF_RADIO->TXADDRESS = 0; // Use logical addr 0
  NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk;
  
  Serial.print(">>> Firing "); Serial.print(recorded_packet_count); Serial.println(" recorded packets...");
  Serial.print("Firing on Ch: "); Serial.print(best_ch_found);
  Serial.print(", Rate: "); Serial.println((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2M" : "1M");
  Serial.print("Address: [0x"); Serial.print(discovered_prefix, HEX); Serial.print("]");
  for(uint8_t i=0; i<discovered_count; i++) { Serial.print(" [0x"); Serial.print(discovered_base[i], HEX); Serial.print("]"); }
  Serial.println();
  
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
  configure_radio_for_state(LISTENING);
}

// =============================================================================
//                            MANUAL ADDRESS ENTRY
// =============================================================================

void set_manual_address(String s) {
  s.trim();
  if (s.length() == 0) { Serial.println("Address string empty."); return; }
  use_preset_mode = false; // Switch to Manual Mode

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
//                                INPUT HANDLING
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
      case 'A': 
        focused_pipe_idx = -1; 
        Serial.println("\nResetting focus to ALL pipes (0-7)");
        if(use_preset_mode) configure_radio_for_state(LISTENING); 
        break;
      case '0' ... '7': 
        focused_pipe_idx = c - '0'; 
        Serial.print("\nFocusing strictly on PIPE "); Serial.println(focused_pipe_idx);
        if(use_preset_mode) configure_radio_for_state(LISTENING);
        break;

      // ---- Discovery ----
      case 'M': 
        Serial.println("Enter full address (Prefix + Base) as hex bytes, space separated:"); 
        entering_address = true; addr_entry = ""; 
        break;
      case 'n': 
        current_preset_idx++; if (current_preset_idx >= NUM_PRESETS) current_preset_idx = 0;
        use_preset_mode = true; // Enable preset mode
        focused_pipe_idx = -1; // Reset pipe focus when changing presets
        Serial.println(F("\nCycling Address Preset (Resetting to ALL pipes)..."));
        Serial.print("Active Preset: ["); Serial.print(current_preset_idx); Serial.print("] "); Serial.println(PRESETS[current_preset_idx]->name);
        configure_radio_for_state(LISTENING);
        if(currentState == IDLE) currentState = LISTENING;
        break;
      case 'X':
        auto_address_discovery(); 
        break;
      case 'Z': clear_manual_address(); break;

      // ---- Record / Fire ----
      case 'R': 
        if (currentState != LISTENING) { Serial.println("Must be in LISTENING mode to record."); break; }
        is_recording = !is_recording; 
        if(is_recording) { 
            recorded_packet_count=0; memset(recorded_packets,0,sizeof(recorded_packets)); 
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
        configure_radio_for_state(LISTENING); // Must restart radio
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
            // If user types digits without pressing 'c' first, ignore or handle as before.
            // In previous code, it fell through. Here we do nothing unless in entry mode.
        } 
        else { Serial.print("Unknown key: "); Serial.println(c); }
        break;
    }
  }
}

// =============================================================================
//                              SETUP & LOOP
// =============================================================================

void setup() {
  pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, HIGH);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  Serial.begin(SERIAL_BAUD);
  unsigned long t0 = millis();
  while (!Serial && millis() - t0 < 1500) {}

  Serial.println("\n--- nRF52840 Sniffer ---");
  Serial.println("<<< nRF24 (TX) and nRF52 (Sniffer) running on same board >>>");

  configure_target_transmitter();
  
  Serial.println("\nInternal nRF52 (Sniffer) ready.");
  Serial.println("Press D7 or 'S' to sweep, or 'c'/'A' to set params.");
  print_help();

  radio_disable();
  currentState = IDLE;
}

bool btn_prev = false;
static bool tx_ok_logged = false; // Tracks if we've confirmed TX works

// =============================================================================
//                              MAIN LOOP
// =============================================================================

void loop() {
  // 1. Target TX
  run_target_transmitter();

  // DIAGNOSTIC: Confirm TX is actually working
  if (!tx_ok_logged) {
    char tx[TARGET_RADIO_PAYLOAD_SIZE] = {0};
    if (radio.write(&tx, 0)) { 
      Serial.println(F("\n>>> TX DIAGNOSTIC: radio.write() Succeeded.\n"));
      tx_ok_logged = true;
    }
  }

  // 2. Button Check
  bool btn = (digitalRead(BUTTON_PIN) == LOW);
  if (btn && !btn_prev) {
    delay(20);
    if (digitalRead(BUTTON_PIN) == LOW) {
      Serial.println(F(">>> Button: starting single sweep..."));
      if (is_recording) { 
        is_recording = false; 
        digitalWrite(LED_PIN, HIGH); 
        Serial.println(F(">>> Recording stopped by sweep button."));
      }
      currentState = SWEEPING; configure_radio_for_state(SWEEPING);
    }
  }
  btn_prev = btn;

  // 3. Serial
  serial_commands();

  // 4. State Machine
  switch (currentState) {
    case IDLE: 
        delay(1); 
        break;

    case SWEEPING: {
      uint8_t found = sweep_once_find_best();
      currentState = ANALYZING; radio_disable();
      Serial.println(F("\n--- Sweep done ---"));
      if (found) { Serial.print(F("Best channel: ")); Serial.println(found); }
      else { Serial.println(F("No channel activity found.")); }
      break;
    }

    case ANALYZING:
      if (best_ch_found) {
        locked = true;
        configure_radio_for_state(LISTENING);
        Serial.print(F(">>> Locked to channel ")); Serial.println(best_ch_found);
        currentState = LISTENING;
      } else {
        locked = false;
        currentState = IDLE; 
        Serial.println(F(">>> Returning to IDLE. Press D7 or 'S' to sweep again."));
      }
      break;

    case LISTENING:
      // PRODUCER: Capture packets from Radio hardware -> Queue
      poll_radio_events();
      
      // CONSUMER: Process packets from Queue -> Serial/Logic
      process_scheduler();
      break;
  }
}