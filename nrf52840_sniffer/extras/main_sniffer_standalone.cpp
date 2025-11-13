/*
 * nRF52840 Sniffer
 * * This script runs on a single nRF52840 board.
 * - The nRF52840 (internal RADIO) acts as the "Sniffer".
 * * The goal is to use the Sniffer UI to find and deconstruct packets
 *   from an external target.
 */

#include <Arduino.h>

// ---------------- Pins / Serial ----------------
#define LED_PIN       LED_BUILTIN
#define BUTTON_PIN    7
#define SERIAL_BAUD   250000

// ---------------- Sweep config -----------------
#define MIN_CH        0
#define MAX_CH        99
#define DWELL_MS      100

// ---------------- Print gate -------------------
static int8_t PRINT_RSSI_THRESH = -30; // dBm

// ---------------- Radio buffer -----------------
#define RADIO_MAX_PAYLOAD 62
// Struct 'esb_rx_t' - defines the nRF52 RADIO's capture buffer structure
typedef struct __attribute__((packed)) {
  uint8_t LENGTH;
  uint8_t S1;
  uint8_t payload[RADIO_MAX_PAYLOAD];
} esb_rx_t;
static esb_rx_t esb_rx_buf;

#define MAX_PDU_SIZE (sizeof(esb_rx_t))

// ---------------- State machine ----------------
enum State { IDLE, SWEEPING, ANALYZING, LISTENING };
static volatile State currentState = IDLE;

// ---------------- Sweep bookkeeping ------------
static uint32_t ch_hits[(MAX_CH - MIN_CH + 1)];
static uint8_t  best_ch_found = MIN_CH;

// ---------------- Runtime radio params ----------
static bool     whitening_enabled = false;
static uint32_t current_mode = RADIO_MODE_MODE_Nrf_2Mbit;
static uint8_t  BALEN           = 1;   // 1..4 valid (address length = BALEN+1 bytes)
static uint8_t  LFLEN           = 0;   // 0..8 bits (payload length field bits)
static uint8_t  S1LEN           = 0;   // 0..7 bits (S1 bits)
static uint8_t  STATLEN         = 32;  // fixed capture length
static uint8_t  current_crc_len = 0;   // 0=Disabled, 1=1 byte, 2=2 bytes
static bool     header_parse_enabled = false;
static bool     locked = false;
static int8_t   bit_shift_amount = 0; // -7 (left) to +7 (right)
static bool     payload_endian_little = false;
static uint8_t  crc_param_profile = 0;
static bool     crc_skip_addr = false;
static uint8_t  preamble_trick_mode = 0; // 0=Off, 1=0xAA, 2=0x55, 3=0xAAAA, 4=0x5555

// ---------------- RSSI tracking -----------------
static volatile int8_t  last_rssi_dbm = -127;
static volatile bool    rssi_ready    = false;

// ---------------- Address discovery -------------
static const uint16_t SCAN_DWELL_MS = 200;
static volatile uint32_t scan_pkt_count  = 0;
static volatile uint32_t scan_addr_count = 0;
static bool suppress_prints = false; // suppress during scans

static bool     have_prefix = false;
static uint8_t  discovered_prefix = 0xAA;
static uint8_t  discovered_base[4] = {0};
static uint8_t  discovered_count = 0;

// ---------------- Record/Replay state ----------
#define MAX_RECORDED_PACKETS 50
#define MAX_RECORDED_PAYLOAD 64

typedef struct {
  uint8_t len;
  uint8_t data[MAX_RECORDED_PAYLOAD];
  uint32_t timestamp_ms; // Record timing between packets
} RecordedPacket;

static RecordedPacket recorded_packets[MAX_RECORDED_PACKETS];
static uint16_t recorded_packet_count = 0;
static bool is_recording = false;

// ---------------- Utils ------------------------
static inline void print_ts() {
  Serial.print('['); Serial.print(millis()); Serial.print(" ms] ");
}
static void print_hex(const uint8_t* b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (b[i] < 0x10) Serial.print('0');
    Serial.print(b[i], HEX);
    Serial.print(' ');
  }
  Serial.println();
}

/**
 * @brief Applies a bit shift to an entire byte array, in-place.
 * Used to correct for bit-alignment issues in received payloads.
 * @param shift_bits Positive=RIGHT, Negative=LEFT
 */
static void apply_bit_shift(uint8_t* buffer, size_t len, int8_t shift_bits) {
  if (len == 0 || shift_bits == 0) return;

  int8_t shift = shift_bits % 8;
  if (shift == 0) return;

  if (shift > 0) {
    // --- Shift RIGHT by 'shift' bits ---
    int8_t rshift = shift;
    uint8_t carry = 0;
    for (int i = (int)len - 1; i >= 0; i--) {
      uint8_t next_carry = (buffer[i] << (8 - rshift));
      buffer[i] = (buffer[i] >> rshift) | carry;
      carry = next_carry;
    }
  } else {
    // --- Shift LEFT by 'abs(shift)' bits ---
    int8_t lshift = -shift;
    uint8_t carry = 0;
    for (size_t i = 0; i < len; i++) {
      uint8_t next_carry = (buffer[i] >> (8 - lshift));
      buffer[i] = (buffer[i] << lshift) | carry;
      carry = next_carry;
    }
  }
}

// Function prototype for new firing function
void fire_recorded_packets();

// ---------------- Low-level RADIO (Sniffer) control -------
static inline void radio_disable() {
  NRF_RADIO->TASKS_DISABLE = 1;
  while (NRF_RADIO->EVENTS_DISABLED == 0) {}
  NRF_RADIO->EVENTS_DISABLED = 0;
}

void set_channel(uint8_t ch) {
  radio_disable();
  NRF_RADIO->FREQUENCY = ch;
  NRF_RADIO->EVENTS_READY   = 0;
  NRF_RADIO->EVENTS_ADDRESS = 0;
  NRF_RADIO->EVENTS_END     = 0;
  NRF_RADIO->EVENTS_RSSIEND = 0;

  rssi_ready = false;
  last_rssi_dbm = -127;
  memset(&esb_rx_buf, 0, sizeof(esb_rx_buf));
  NRF_RADIO->PACKETPTR = (uint32_t)&esb_rx_buf;
  NRF_RADIO->TASKS_RXEN = 1;
}

/**
 * @brief Applies PCNF0 and PCNF1 settings, handling the
 * Preamble Trick mode override.
 */
void apply_pcnf0_pcnf1() {
  if (preamble_trick_mode > 0) {
    // --- PREAMBLE "TRICK" MODE ---
    // Use the preamble (e.g., 0xAA) as the address by setting PLEN=0
    uint8_t trick_balen = 0;
    switch (preamble_trick_mode) {
      case 1: // 0xAA
      case 2: // 0x55
        trick_balen = 0; // 1-byte address
        break;
      case 3: // 0xAAAA
      case 4: // 0x5555
        trick_balen = 1; // 2-byte address
        break;
    }

    NRF_RADIO->PCNF0 =
      (0 << RADIO_PCNF0_S0LEN_Pos) |
      (LFLEN << RADIO_PCNF0_LFLEN_Pos) |
      (S1LEN << RADIO_PCNF0_S1LEN_Pos) |
      (3 << RADIO_PCNF0_PLEN_Pos); // Use 3 for 0-bit preamble (undocumented)

    uint32_t pcnf1 = 0;
    pcnf1 |= (whitening_enabled ? RADIO_PCNF1_WHITEEN_Enabled : RADIO_PCNF1_WHITEEN_Disabled) << RADIO_PCNF1_WHITEEN_Pos;
    pcnf1 |= (payload_endian_little ? RADIO_PCNF1_ENDIAN_Little : RADIO_PCNF1_ENDIAN_Big) << RADIO_PCNF1_ENDIAN_Pos;
    pcnf1 |= (trick_balen << RADIO_PCNF1_BALEN_Pos); // Use trick BALEN
    pcnf1 |= (STATLEN << RADIO_PCNF1_STATLEN_Pos);
    pcnf1 |= (RADIO_MAX_PAYLOAD << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->PCNF1 = pcnf1;

  } else {
    // --- NORMAL ADDRESS DISCOVERY MODE ---
    NRF_RADIO->PCNF0 =
      (0 << RADIO_PCNF0_S0LEN_Pos) |
      (LFLEN << RADIO_PCNF0_LFLEN_Pos) |
      (S1LEN << RADIO_PCNF0_S1LEN_Pos) |
      (RADIO_PCNF0_PLEN_8bit << RADIO_PCNF0_PLEN_Pos); // Default 8-bit preamble

    uint32_t pcnf1 = 0;
    pcnf1 |= (whitening_enabled ? RADIO_PCNF1_WHITEEN_Enabled : RADIO_PCNF1_WHITEEN_Disabled) << RADIO_PCNF1_WHITEEN_Pos;
    pcnf1 |= (payload_endian_little ? RADIO_PCNF1_ENDIAN_Little : RADIO_PCNF1_ENDIAN_Big) << RADIO_PCNF1_ENDIAN_Pos;
    pcnf1 |= (BALEN << RADIO_PCNF1_BALEN_Pos); // Use normal BALEN
    pcnf1 |= (STATLEN << RADIO_PCNF1_STATLEN_Pos);
    pcnf1 |= (RADIO_MAX_PAYLOAD << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->PCNF1 = pcnf1;
  }
}

/**
 * @brief Configures all base nRF52 RADIO settings (CRC, Address, etc.)
 * This handles Preamble Trick mode vs. normal Address Discovery.
 */
void radio_base_config() {
  NRF_CLOCK->EVENTS_HFCLKSTARTED = 0;
  NRF_CLOCK->TASKS_HFCLKSTART = 1;
  while (NRF_CLOCK->EVENTS_HFCLKSTARTED == 0) {}

  NRF_RADIO->MODE = current_mode << RADIO_MODE_MODE_Pos;

  apply_pcnf0_pcnf1();

  // --- Address Logic ---
  if (preamble_trick_mode > 0) {
    // Preamble "Trick" Mode: Override address with preamble patterns
    uint8_t trick_prefix = 0;
    uint32_t trick_base = 0;

    switch (preamble_trick_mode) {
      case 1: trick_prefix = 0xAA; trick_base = 0;    break; // 0xAA
      case 2: trick_prefix = 0x55; trick_base = 0;    break; // 0x55
      case 3: trick_prefix = 0xAA; trick_base = 0xAA; break; // 0xAAAA
      case 4: trick_prefix = 0x55; trick_base = 0x55; break; // 0x5555
    }

    NRF_RADIO->BASE0   = trick_base;
    NRF_RADIO->BASE1   = 0x00000000UL;
    NRF_RADIO->PREFIX0 = trick_prefix;
    NRF_RADIO->PREFIX1 = 0;
    NRF_RADIO->RXADDRESSES = (1 << 0);

  } else {
    // Normal Address Discovery Mode
    if (have_prefix) {
      NRF_RADIO->PREFIX0 = discovered_prefix;
      NRF_RADIO->PREFIX1 = 0;
      NRF_RADIO->RXADDRESSES = (1 << 0);

      uint32_t final_base = 0;
      for (uint8_t i = 0; i < discovered_count; i++) {
        final_base |= ((uint32_t)discovered_base[i]) << (8 * i);
      }
      NRF_RADIO->BASE0 = final_base;
      NRF_RADIO->BASE1 = 0x00000000UL;
    } else {
      // Default settings (no address found yet)
      NRF_RADIO->BASE0    = 0x00000000UL;
      NRF_RADIO->BASE1    = 0x00000000UL;
      NRF_RADIO->PREFIX0  = 0xAA; // Default prefix to sniff
      NRF_RADIO->PREFIX1  = 0x00000000UL;
      NRF_RADIO->RXADDRESSES = (1 << 0);
    }
  }

  // --- CRC Poly/Init Profile ---
  switch (crc_param_profile) {
    case 0: // Default: nRF24, CCITT-FALSE
      NRF_RADIO->CRCPOLY = 0x00001021UL;
      NRF_RADIO->CRCINIT = 0x0000FFFFUL;
      break;
    case 1: // Kermit
      NRF_RADIO->CRCPOLY = 0x00001021UL;
      NRF_RADIO->CRCINIT = 0x00000000UL;
      break;
    case 2: // Modbus / CRC-16-IBM
      NRF_RADIO->CRCPOLY = 0x00008005UL;
      NRF_RADIO->CRCINIT = 0x0000FFFFUL;
      break;
    case 3: // ARC / CRC-16
      NRF_RADIO->CRCPOLY = 0x00008005UL;
      NRF_RADIO->CRCINIT = 0x00000000UL;
      break;
  }

  // Apply configurable CRC length
  uint32_t crc_val = RADIO_CRCCNF_LEN_Disabled;
  if (current_crc_len == 1) crc_val = RADIO_CRCCNF_LEN_One;
  else if (current_crc_len == 2) crc_val = RADIO_CRCCNF_LEN_Two;

  uint32_t crc_conf_val = (crc_val << RADIO_CRCCNF_LEN_Pos);

  if (crc_skip_addr) {
    crc_conf_val |= (RADIO_CRCCNF_SKIPADDR_Skip << RADIO_CRCCNF_SKIPADDR_Pos);
  }
  NRF_RADIO->CRCCNF = crc_conf_val;

  // Continuous RX
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

// ---------------- Discovery reset/undo -----------
void discovery_reset_all() {
  have_prefix = false;
  discovered_prefix = 0xAA;
  memset(discovered_base, 0, sizeof(discovered_base));
  discovered_count = 0;

  BALEN = 1;
  restore_single_pipe_prefix(0xAA);
  set_channel(best_ch_found);
  Serial.println(">>> Discovery reset: prefix cleared, base bytes cleared, BALEN=1, default 0xAA single-pipe restored.");
}

// ---------------- Parameter dump ----------------
void print_params() {
  Serial.println(F("\n--- Current Settings ---"));
  Serial.print (F("State: "));
  switch (currentState) {
    case IDLE:      Serial.println(F("IDLE")); break;
    case SWEEPING:  Serial.println(F("SWEEPING")); break;
    case ANALYZING: Serial.println(F("ANALYZING")); break;
    case LISTENING: Serial.println(F("LISTENING")); break;
  }
  Serial.print (F("Locked channel: ")); Serial.println(best_ch_found);
  Serial.print (F("Data rate: ")); Serial.println((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2 Mbps" : "1 Mbps");
  Serial.print (F("Whitening: ")); Serial.println(whitening_enabled ? "ENABLED" : "DISABLED");
  Serial.print (F("BALEN: ")); Serial.println(BALEN);
  Serial.print (F("LFLEN: ")); Serial.println(LFLEN);
  Serial.print (F("S1LEN: ")); Serial.println(S1LEN);
  Serial.print (F("STATLEN: ")); Serial.println(STATLEN);
  Serial.print (F("Header parse: ")); Serial.println(header_parse_enabled ? "ENABLED" : "DISABLED");
  Serial.print (F("Payload Endian: ")); Serial.println(payload_endian_little ? "Little (nRF)" : "Big (BLE)");
  Serial.print (F("RSSI print threshold: ")); Serial.print(PRINT_RSSI_THRESH); Serial.println(F(" dBm"));

  Serial.print (F("CRC: "));
  if (current_crc_len == 0)      Serial.println(F("DISABLED"));
  else if (current_crc_len == 1) Serial.println(F("1 Byte"));
  else if (current_crc_len == 2) Serial.println(F("2 Bytes"));

  Serial.print (F("CRC Skip Address: ")); Serial.println(crc_skip_addr ? "Skip (Payload Only)" : "Include (Addr + Payload)");

  Serial.print (F("CRC Profile: "));
  switch (crc_param_profile) {
    case 0: Serial.println(F("0: Default (Poly:0x1021, Init:0xFFFF)")); break;
    case 1: Serial.println(F("1: Kermit (Poly:0x1021, Init:0x0000)")); break;
    case 2: Serial.println(F("2: Modbus (Poly:0x8005, Init:0xFFFF)")); break;
    case 3: Serial.println(F("3: ARC (Poly:0x8005, Init:0x0000)")); break;
  }

  Serial.print (F("Preamble Sniff Trick: "));
  switch (preamble_trick_mode) {
    case 0: Serial.println(F("DEFAULT (Using Address Discovery)")); break;
    case 1: Serial.println(F("ON: 0xAA (1-byte)")); break;
    case 2: Serial.println(F("ON: 0x55 (1-byte)")); break;
    case 3: Serial.println(F("ON: 0xAAAA (2-byte)")); break;
    case 4: Serial.println(F("ON: 0x5555 (2-byte)")); break;
  }

  Serial.print (F("Bit Shift: ")); Serial.println(bit_shift_amount);

  // Only print discovery info if Preamble Trick is OFF
  if (preamble_trick_mode == 0) {
    Serial.print (F("Discovered Addr: "));
    if (have_prefix) { Serial.print(F("0x")); Serial.print(discovered_prefix, HEX); }
    else { Serial.print(F("(none)")); }
    Serial.print(F(" + ")); Serial.print(discovered_count); Serial.println(F(" base byte(s)"));
    Serial.print(F("Discovered base (LSB->MSB): "));
    if (discovered_count == 0) Serial.println(F("(none)"));
    else {
      for (uint8_t i = 0; i < discovered_count; i++) {
        Serial.print("0x"); Serial.print(discovered_base[i], HEX);
        if (i < discovered_count - 1) Serial.print(" ");
      }
      Serial.println();
    }
  }

  Serial.print(F("Recorded packets: ")); Serial.print(recorded_packet_count);
  Serial.print(F(" / ")); Serial.println(MAX_RECORDED_PACKETS);
  Serial.println(F("------------------------\n"));
}

void discovery_undo_last_byte() {
  if (discovered_count == 0) {
    Serial.println("Nothing to undo: no base bytes discovered yet.");
    return;
  }
  discovered_count--;
  Serial.print(">>> Undid base byte #"); Serial.println(discovered_count);

  uint32_t base = 0;
  for (uint8_t i = 0; i < discovered_count; i++)
    base |= ((uint32_t)discovered_base[i]) << (8 * i);
  NRF_RADIO->BASE0 = base;

  BALEN = (discovered_count == 0) ? 1 : discovered_count;

  if (have_prefix) restore_single_pipe_prefix(discovered_prefix);
  else restore_single_pipe_prefix(0xAA);

  set_channel(best_ch_found);
  print_params();
}

// ---------------- Event processing ----------------
/**
 * @brief This is the main packet processing function.
 * It checks for RADIO events (ADDRESS, RSSIEND, END),
 * determines payload length, records packets, and prints to serial.
 */
void poll_radio_events(uint8_t channel, bool allow_prints) {
  if (NRF_RADIO->EVENTS_ADDRESS) {
    NRF_RADIO->EVENTS_ADDRESS = 0;

    // Start RSSI sampling as soon as address is matched
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
  if (NRF_RADIO->EVENTS_END) {
    NRF_RADIO->EVENTS_END = 0;
    scan_pkt_count++;

    int8_t rssi = rssi_ready ? last_rssi_dbm : -127;

    bool crc_ok = true;
    if (current_crc_len > 0) {
      crc_ok = (NRF_RADIO->CRCSTATUS == 1);
    }

    // --- Determine true payload start and length ---
    uint8_t* payload_start_ptr;
    size_t   payload_actual_len;
    size_t   max_payload_bytes_in_buffer;
    bool     plen_is_zero = (preamble_trick_mode > 0);

    if (LFLEN > 0 && !plen_is_zero) {
      // Dynamic length (and not Preamble Trick mode)
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
      // Static length OR Preamble Trick mode
      payload_start_ptr = (uint8_t*)&esb_rx_buf.LENGTH;
      max_payload_bytes_in_buffer = RADIO_MAX_PAYLOAD + 2;
      payload_actual_len = (STATLEN == 0 || STATLEN > max_payload_bytes_in_buffer)
                           ? max_payload_bytes_in_buffer
                           : STATLEN;
    }

    if (payload_actual_len > max_payload_bytes_in_buffer) {
      payload_actual_len = max_payload_bytes_in_buffer;
    }
    if (payload_actual_len > MAX_PDU_SIZE) {
      payload_actual_len = MAX_PDU_SIZE;
    }
    // --- End length calculation ---

    if (rssi_ready && rssi >= PRINT_RSSI_THRESH && crc_ok) {
      scan_addr_count++; // Count as a valid "hit"

      // --- Packet Recording Logic ---
      if (is_recording && recorded_packet_count < MAX_RECORDED_PACKETS) {
        uint8_t* pdu_start = (uint8_t*)&esb_rx_buf.LENGTH;
        size_t pdu_total_len;

        if (LFLEN > 0 && !plen_is_zero) {
          size_t header_size = 1 + (S1LEN > 0 ? 1 : 0);
          pdu_total_len = header_size + payload_actual_len;
        } else {
          pdu_total_len = payload_actual_len;
        }

        if (pdu_total_len > MAX_RECORDED_PAYLOAD) {
          pdu_total_len = MAX_RECORDED_PAYLOAD;
        }

        if (pdu_total_len > 0) {
          recorded_packets[recorded_packet_count].len = (uint8_t)pdu_total_len;
          memcpy(recorded_packets[recorded_packet_count].data, pdu_start, pdu_total_len);
          recorded_packets[recorded_packet_count].timestamp_ms = millis();
          recorded_packet_count++;

          // Blink LED "off" (it's solid on) to show packet capture
          digitalWrite(LED_PIN, HIGH);
          delay(10);
          digitalWrite(LED_PIN, LOW);
        }
      }
    }

    // --- Printing ---
    if (allow_prints && !suppress_prints) {
      if (rssi >= PRINT_RSSI_THRESH) {
        uint8_t pipe = NRF_RADIO->RXMATCH & 0x07;
        print_ts();
        Serial.print("Ch "); Serial.print(channel);
        Serial.print(" pipe="); Serial.print(pipe);
        Serial.print(" RSSI="); Serial.print(rssi); Serial.print(" dBm");

        if (current_crc_len > 0) {
          Serial.print(crc_ok ? " CRC=OK " : " CRC=BAD ");
        } else {
          Serial.print("   -> ");
        }

        if (crc_ok) {
          if (header_parse_enabled && LFLEN > 0 && !plen_is_zero) {
            uint8_t lmask = (LFLEN >= 8) ? 0xFFu : (uint8_t)((1u << LFLEN) - 1u);
            uint8_t length_from_field = esb_rx_buf.LENGTH & lmask;
            Serial.print("LEN="); Serial.print(length_from_field);
            if (S1LEN > 0) {
              uint8_t s1mask = (S1LEN == 0) ? 0 : (uint8_t)((1u << S1LEN) - 1u);
              uint8_t s1 = esb_rx_buf.S1 & s1mask;
              Serial.print(" S1=0x"); Serial.print(s1, HEX);
            }
            Serial.print(" -> ");
          }

          // --- Apply bit shift before printing ---
          if (bit_shift_amount != 0) {
            uint8_t shifted_payload[MAX_PDU_SIZE];
            size_t len_to_process = (payload_actual_len > MAX_PDU_SIZE) ? MAX_PDU_SIZE : payload_actual_len;
            if (len_to_process > 0) {
              memcpy(shifted_payload, payload_start_ptr, len_to_process);
              apply_bit_shift(shifted_payload, len_to_process, bit_shift_amount);
            }
            print_hex(shifted_payload, len_to_process);
          } else {
            // No shift, print original
            print_hex(payload_start_ptr, payload_actual_len);
          }
        } else {
          Serial.println(); // CRC bad
        }
      }
    }

    // Reset for next packet
    memset(&esb_rx_buf, 0, sizeof(esb_rx_buf));
    rssi_ready = false;
    last_rssi_dbm = -127;
  }
}

// ----------------------- FIXED SWEEPER -----------------------
static inline void start_rx_for_sweep(uint8_t ch) {
  set_channel(ch);
  NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_END_START_Msk;
}

/**
 * @brief Sweeps all channels (MIN_CH to MAX_CH) once and finds the
 * channel with the most valid packets (gated by RSSI and CRC).
 * @return The best channel found, or 0 if no activity.
 */
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

// ---------------- Address discovery ----------------
/**
 * @brief Brute-force scan for the 1-byte prefix (0x00..0xFF).
 * Requires LISTENING on a locked channel.
 */
bool run_prefix_scan() {
  if (currentState != LISTENING) {
    Serial.println("Prefix scan requires LISTENING (locked channel). Sweep first.");
    return false;
  }
  if (preamble_trick_mode > 0) {
    Serial.println("Preamble Sniff Trick is ON. Disable with 'a' to use Address Discovery.");
    return false;
  }

  Serial.println("\n--- Prefix scan: starting (0x00..0xFF individually) ---");
  Serial.println("Tip: hold the device's button so your traffic dominates.");

  uint8_t  saved_BALEN   = BALEN;
  uint32_t saved_PREFIX0 = NRF_RADIO->PREFIX0;
  uint32_t saved_PREFIX1 = NRF_RADIO->PREFIX1;
  uint32_t saved_RXADDR  = NRF_RADIO->RXADDRESSES;
  uint32_t saved_BASE0   = NRF_RADIO->BASE0;

  BALEN = 1; // Force 1-byte base (2-byte total address) for prefix scan
  apply_pcnf0_pcnf1();
  suppress_prints = true;

  struct Cand { uint8_t p; uint32_t hits; };
  Cand top[5]; for (int i = 0; i < 5; i++) { top[i] = {0,0}; }

  const uint16_t dwell = SCAN_DWELL_MS;
  uint32_t last_pct = 0;

  for (uint16_t pref = 0; pref <= 0xFF; ++pref) {
    NRF_RADIO->PREFIX0 = (uint32_t)(uint8_t)pref;
    NRF_RADIO->PREFIX1 = 0;
    NRF_RADIO->RXADDRESSES = (1 << 0);
    NRF_RADIO->BASE0 = 0x00000000;
    set_channel(best_ch_found);

    scan_addr_count = 0;
    uint32_t t0 = millis();
    while (millis() - t0 < dwell) {
      poll_radio_events(best_ch_found, false);
    }

    uint32_t h = scan_addr_count;
    for (int i = 0; i < 5; i++) {
      if (h > top[i].hits) {
        for (int j = 4; j > i; --j) top[j] = top[j-1];
        top[i] = { (uint8_t)pref, h };
        break;
      }
    }

    uint32_t pct = ((pref + 1) * 100UL) / 256UL;
    if (pct >= last_pct + 4) {
      Serial.print("Progress: "); Serial.print(pct); Serial.println("%");
      last_pct = pct;
    }
  }

  // --- Validation phase ---
  const uint16_t validate_ms = 300;
  const uint32_t min_hits    = 5;
  uint8_t best_prefix = 0;
  uint32_t best_hits  = 0;

  Serial.println("Validating top prefixes...");
  for (int i = 0; i < 5; i++) {
    if (top[i].hits == 0) continue;
    uint8_t p = top[i].p;

    NRF_RADIO->PREFIX0 = p;
    NRF_RADIO->PREFIX1 = 0;
    NRF_RADIO->RXADDRESSES = (1 << 0);
    NRF_RADIO->BASE0 = 0x00000000;
    set_channel(best_ch_found);

    scan_addr_count = 0;
    uint32_t t0 = millis();
    while (millis() - t0 < validate_ms) {
      poll_radio_events(best_ch_found, false);
    }
    Serial.print("   cand 0x"); Serial.print(p, HEX);
    Serial.print(" -> ADDRESS hits="); Serial.println((uint32_t)scan_addr_count);
    if (scan_addr_count > best_hits) {
      best_hits = scan_addr_count;
      best_prefix = p;
    }
  }

  // --- Restore settings ---
  suppress_prints = false;
  NRF_RADIO->PREFIX0 = saved_PREFIX0;
  NRF_RADIO->PREFIX1 = saved_PREFIX1;
  NRF_RADIO->RXADDRESSES = saved_RXADDR;
  NRF_RADIO->BASE0 = saved_BASE0;
  BALEN = saved_BALEN;
  apply_pcnf0_pcnf1();

  if (best_hits >= min_hits) {
    discovered_prefix = best_prefix;
    have_prefix = true;

    // Apply the *new* found prefix
    restore_single_pipe_prefix(discovered_prefix);
    NRF_RADIO->BASE0 = 0x00000000; // Base is 0 for now
    BALEN = 1;
    apply_pcnf0_pcnf1();
    set_channel(best_ch_found);

    Serial.print(">>> Prefix found & validated: 0x");
    Serial.print(discovered_prefix, HEX);
    Serial.print(" (hits="); Serial.print(best_hits); Serial.println(")");
    Serial.print(">>> Radio locked to [0x"); Serial.print(discovered_prefix, HEX); Serial.println("][0x00]");
    Serial.println(">>> Press 'Y' to find the next base byte.");
    return true;
  } else {
    set_channel(best_ch_found);
    Serial.println(">>> No stable prefix validated. Try again.");
    return false;
  }
}

/**
 * @brief Brute-force scan for the *next* base address byte (0x00..0xFF).
 * Requires a known prefix.
 */
bool run_next_byte_scan(uint8_t *found_byte) {
  if (!have_prefix) {
    Serial.println("Next-byte scan needs a known prefix. Press 'X' first.");
    return false;
  }
  if (currentState != LISTENING) {
    Serial.println("Next-byte scan requires LISTENING (locked channel). Sweep first.");
    return false;
  }
  if (preamble_trick_mode > 0) {
    Serial.println("Preamble Sniff Trick is ON. Disable with 'a' to use Address Discovery.");
    return false;
  }

  uint8_t target_index = discovered_count; // This is the byte we are looking for (0-3)
  if (target_index >= 4) {
    Serial.println("Already have 4 base bytes.");
    return false;
  }

  Serial.print("\n--- Next-byte scan (discovering base byte #");
  Serial.print(target_index); Serial.println(") ---");
  Serial.println("Tip: keep transmitting (press the button).");
  suppress_prints = true;

  uint8_t saved_BALEN = BALEN;
  BALEN = target_index + 1; // e.g., finding byte 0 -> BALEN=1 (2-byte addr)
  apply_pcnf0_pcnf1();
  restore_single_pipe_prefix(discovered_prefix);

  uint32_t base_so_far = 0;
  for (uint8_t i = 0; i < discovered_count; ++i) {
    base_so_far |= ((uint32_t)discovered_base[i]) << (8 * i);
  }

  uint8_t best_b = 0;
  uint32_t best_hits = 0;
  uint32_t last_pct = 0;

  for (uint16_t b = 0; b <= 0xFF; ++b) {
    uint32_t test_base = base_so_far | ((uint32_t)b << (8 * target_index));
    NRF_RADIO->BASE0 = test_base;

    set_channel(best_ch_found);
    scan_addr_count = 0;
    uint32_t t0 = millis();
    while (millis() - t0 < SCAN_DWELL_MS) {
      poll_radio_events(best_ch_found, false);
    }

    if (scan_addr_count > best_hits) { best_hits = scan_addr_count; best_b = (uint8_t)b; }

    uint32_t pct = ((b + 1) * 100UL) / 256UL;
    if (pct >= last_pct + 8) {
      Serial.print("Progress: "); Serial.print(pct);
      Serial.print("%   current best=0x"); Serial.print(best_b, HEX);
      Serial.print(" (hits="); Serial.print(best_hits); Serial.println(")");
      last_pct = pct;
    }
  }

  suppress_prints = false;

  // Restore original BALEN and BASE0 in case of failure
  if (best_hits == 0) {
    BALEN = saved_BALEN;
    apply_pcnf0_pcnf1();
    NRF_RADIO->BASE0 = base_so_far;
    set_channel(best_ch_found);
  }

  if (best_hits > 0) {
    *found_byte = best_b;
    if (discovered_count < 4) {
      discovered_base[discovered_count] = best_b;
      discovered_count++;
    }

    BALEN = discovered_count; // e.g., found byte 0 -> BALEN=1
    apply_pcnf0_pcnf1();
    restore_single_pipe_prefix(discovered_prefix);

    uint32_t final_base = 0;
    for (uint8_t i = 0; i < discovered_count; i++) {
      final_base |= ((uint32_t)discovered_base[i]) << (8 * i);
    }
    NRF_RADIO->BASE0 = final_base;
    set_channel(best_ch_found);

    Serial.print(">>> Discovered base byte #");
    Serial.print(target_index);
    Serial.print(": 0x"); Serial.print(best_b, HEX);
    Serial.print("  (hits="); Serial.print(best_hits); Serial.println(")");
    Serial.print(">>> Applied PREFIX 0x"); Serial.print(discovered_prefix, HEX);
    Serial.print(" + "); Serial.print(discovered_count); Serial.println(" base byte(s).");
    return true;
  } else {
    Serial.println(">>> No clear winner in next-byte scan.");
    return false;
  }
}

// ---------------- Replay / Firing function ----------------
/**
 * @brief Transmits all recorded packets using the current sniffer settings
 * (Channel, Rate, Address, CRC, etc.) with recorded timing.
 */
void fire_recorded_packets() {
  if (recorded_packet_count == 0) {
    Serial.println("No packets to fire.");
    return;
  }

  radio_disable();

  // Configure TX mode using all current sniffer params
  radio_base_config();

  NRF_RADIO->TXADDRESS = 0; // Use logical address 0
  NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk; // Just READY->START

  Serial.print("Firing on Ch: "); Serial.print(best_ch_found);
  Serial.print(", Rate: "); Serial.println((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2M" : "1M");

  if (preamble_trick_mode == 0) {
    Serial.print("Address: [0x"); Serial.print(discovered_prefix, HEX); Serial.print("]");
    for (uint8_t i = 0; i < discovered_count; i++) {
      Serial.print(" [0x"); Serial.print(discovered_base[i], HEX); Serial.print("]");
    }
    Serial.println();
  } else {
    Serial.print("Address (Preamble Trick): ");
    switch (preamble_trick_mode) {
      case 1: Serial.println(F("0xAA")); break;
      case 2: Serial.println(F("0x55")); break;
      case 3: Serial.println(F("0xAAAA")); break;
      case 4: Serial.println(F("0x5555")); break;
    }
  }

  NRF_RADIO->FREQUENCY = best_ch_found;

  // --- Timed TX Logic ---
  uint32_t tx_start_time_ms = millis(); // The wall-clock time our TX sequence starts
  uint32_t rx_start_time_ms = recorded_packets[0].timestamp_ms; // The "zero-point" of the recording

  for (uint16_t i = 0; i < recorded_packet_count; i++) {
    if (recorded_packets[i].len == 0 || recorded_packets[i].len > MAX_RECORDED_PAYLOAD) {
      continue;
    }

    // Calculate when this packet *should* be sent
    uint32_t rx_delta_ms = recorded_packets[i].timestamp_ms - rx_start_time_ms;
    uint32_t target_tx_time_ms = tx_start_time_ms + rx_delta_ms;

    // Wait until it's time to send
    while (millis() < target_tx_time_ms) {
      delay(1);
    }

    NRF_RADIO->PACKETPTR = (uint32_t)recorded_packets[i].data;

    bool plen_is_zero = (preamble_trick_mode > 0);

    // In static length mode, we must update STATLEN for *each packet*
    if (LFLEN == 0 || plen_is_zero) {
      uint32_t pcnf1 = NRF_RADIO->PCNF1;
      pcnf1 &= ~(RADIO_PCNF1_STATLEN_Msk);
      pcnf1 |= (recorded_packets[i].len << RADIO_PCNF1_STATLEN_Pos);
      NRF_RADIO->PCNF1 = pcnf1;
    }

    // Start TX
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->TASKS_TXEN = 1;

    // Wait for TX to complete (with timeout)
    unsigned long tx_start_wait = millis();
    while (NRF_RADIO->EVENTS_END == 0 && (millis() - tx_start_wait < 50)) {}
    NRF_RADIO->EVENTS_END = 0;

    // Disable TX
    NRF_RADIO->TASKS_DISABLE = 1;
    while (NRF_RADIO->EVENTS_DISABLED == 0) {}
    NRF_RADIO->EVENTS_DISABLED = 0;
  }

  // Re-enable sniffer
  Serial.println("TX complete. Re-enabling sniffer...");
  configure_radio_for_state(LISTENING);
}

// ---------------- Manual Address Setting ----------
void set_manual_address(String s) {
  if (preamble_trick_mode > 0) {
    Serial.println("Preamble Sniff Trick is ON. Disable with 'a' to set manual address.");
    return;
  }

  s.trim();
  if (s.length() == 0) {
    Serial.println("Address string empty.");
    return;
  }

  // Reset discovery
  have_prefix = false;
  discovered_count = 0;
  memset(discovered_base, 0, sizeof(discovered_base));

  int start_idx = 0;
  int end_idx = s.indexOf(' ');
  bool first_byte = true;
  uint32_t final_base = 0;

  while (start_idx < (int)s.length()) {
    if (end_idx == -1) end_idx = s.length(); // Handle last byte

    String byte_str = s.substring(start_idx, end_idx);
    byte_str.trim();

    if (byte_str.length() > 0) {
      byte b = (byte)strtoul(byte_str.c_str(), NULL, 16);

      if (first_byte) {
        discovered_prefix = b;
        have_prefix = true;
        first_byte = false;
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
    currentState = LISTENING; // Force state change
  }

  Serial.println(">>> Manual address set.");
  print_params();
}

// ---------------- UI / Keyboard ----------------
void print_help() {
  Serial.println(F("\nKeys:"));
  Serial.println(F("  h : help"));
  Serial.println(F("  S : run a single sweep"));
  Serial.println(F("  P : print current parameter settings"));
  Serial.println(F("  T : set exact RSSI threshold in dBm (e.g., -55) then Enter"));
  Serial.println(F("  [ : raise RSSI threshold by +5 dB"));
  Serial.println(F("  ] : lower RSSI threshold by -5 dB"));
  Serial.println(F("  --------------------------- Discovery ---------------------------"));
  Serial.println(F("  A : (Uppercase) set manual address (e.g., AA 12 34)"));
  Serial.println(F("  X : prefix scan (validated; uses ADDRESS hits)"));
  Serial.println(F("  Y : next-byte scan (prefix fixed; brute-force next byte)"));
  Serial.println(F("  U : undo last discovered base byte"));
  Serial.println(F("  Z : reset discovery (clear prefix + base bytes)"));
  Serial.println(F("  ------------------------- Record / Fire -------------------------"));
  Serial.println(F("  R : (Uppercase) toggle packet recording (LISTENING only)"));
  Serial.println(F("  f : (lowercase) fire (transmit) recorded packets"));
  Serial.println(F("  ---------------------- Sniffer (LISTENING) ----------------------"));
  Serial.println(F("  W : toggle whitening"));
  Serial.println(F("  D : toggle data rate (1M/2M)"));
  Serial.println(F("  b : cycle BALEN (1..4)"));
  Serial.println(F("  l : cycle LFLEN (0..8)"));
  Serial.println(F("  s : cycle S1LEN (0..7)"));
  Serial.println(F("  t : cycle STATLEN (0/6/8/16/24/32/64)"));
  Serial.println(F("  K : (Uppercase) set exact STATLEN (0-255) then Enter"));
  Serial.println(F("  C : (Uppercase) cycle CRC (Off/1B/2B)"));
  Serial.println(F("  V : (Uppercase) cycle CRC Profile (Poly/Init)"));
  Serial.println(F("  e : cycle Payload Endianness (Little/Big)"));
  Serial.println(F("  i : cycle CRC Skip Address (Include/Skip)"));
  Serial.println(F("  a : cycle Preamble Sniff Trick (Default/AA/55/AAAA/5555)"));
  Serial.println(F("  p : toggle header parsing (LEN/S1)"));
  Serial.println(F("  < / > : bit-shift printed payload left/right (-7 to +7)"));
  Serial.println(F("  + / - : channel up/down"));
  Serial.println(F("  c : enter channel number + Enter"));
  Serial.println(F("  r : (lowercase) reapply radio with current params"));
  Serial.print  (F("\nRSSI print gate: ")); Serial.print(PRINT_RSSI_THRESH); Serial.println(F(" dBm"));
}

String chan_entry;
String thresh_entry;
String addr_entry;
String statlen_entry;
bool entering_thresh = false;
bool entering_address = false;
bool entering_statlen = false;

void serial_commands() {
  while (Serial.available()) {
    char c = Serial.read();

    if (c == '\r' || c == '\n') {
      if (chan_entry.length()) {
        int ch = chan_entry.toInt();
        chan_entry = "";
        if (ch >= MIN_CH && ch <= MAX_CH) {
          best_ch_found = (uint8_t)ch;

          if (currentState == IDLE) {
            Serial.println(">>> IDLE exit: Manual channel set.");
            configure_radio_for_state(LISTENING);
            currentState = LISTENING;
          } else {
            set_channel(best_ch_found);
          }

          Serial.print("Channel set to "); Serial.println(best_ch_found);
        } else {
          Serial.println("Channel out of range.");
        }
      }

      if (entering_thresh && thresh_entry.length()) {
        int val = thresh_entry.toInt();
        if (val < -100) val = -100;
        if (val > -20)  val = -20;
        PRINT_RSSI_THRESH = (int8_t)val;
        Serial.print("RSSI print threshold set to "); Serial.print(PRINT_RSSI_THRESH); Serial.println(" dBm");
        entering_thresh = false;
        thresh_entry = "";
      }
      if (entering_address && addr_entry.length()) {
        set_manual_address(addr_entry);
        entering_address = false;
        addr_entry = "";
      }

      if (entering_statlen && statlen_entry.length()) {
        int len = statlen_entry.toInt();
        if (len < 0) len = 0;
        if (len > 255) len = 255;
        STATLEN = (uint8_t)len;
        apply_pcnf0_pcnf1();
        Serial.print("STATLEN manually set to "); Serial.println(STATLEN);
        entering_statlen = false;
        statlen_entry = "";
      }

      continue;
    }

    if (chan_entry.length()) {
      if (isDigit(c)) { chan_entry += c; Serial.print(c); continue; }
      else chan_entry = "";
    }

    if (entering_thresh && (isDigit(c) || c == '-')) {
      thresh_entry += c; Serial.print(c); continue;
    } else if (entering_thresh && !(c == '\r' || c == '\n')) {
      entering_thresh = false; thresh_entry = "";
    }

    if (entering_address && (isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ' ')) {
      addr_entry += c; Serial.print(c); continue;
    } else if (entering_address) {
      entering_address = false; addr_entry = "";
    }

    if (entering_statlen && isDigit(c)) {
      statlen_entry += c; Serial.print(c); continue;
    } else if (entering_statlen && !(c == '\r' || c == '\n')) {
      entering_statlen = false; statlen_entry = "";
    }

    switch (c) {
      case 'h': case 'H': print_help(); break;
      case 'P': print_params(); break;

      case '[': {
        int newv = (int)PRINT_RSSI_THRESH + 5;
        if (newv > -20) newv = -20;
        PRINT_RSSI_THRESH = (int8_t)newv;
        Serial.print("RSSI print threshold = "); Serial.print(PRINT_RSSI_THRESH); Serial.println(" dBm");
        break;
      }
      case ']': {
        int newv = (int)PRINT_RSSI_THRESH - 5;
        if (newv < -100) newv = -100;
        PRINT_RSSI_THRESH = (int8_t)newv;
        Serial.print("RSSI print threshold = "); Serial.print(PRINT_RSSI_THRESH); Serial.println(" dBm");
        break;
      }
      case 'T':
        Serial.println("Enter RSSI threshold in dBm (e.g., -55) then Enter:");
        entering_thresh = true; thresh_entry = "";
        break;

      case 'S':
        Serial.println(">>> Starting single sweep...");
        currentState = SWEEPING;
        configure_radio_for_state(SWEEPING);
        break;

      case 'Z':
        discovery_reset_all();
        break;

      case 'U':
        discovery_undo_last_byte();
        break;

      case 'A': {
        if (preamble_trick_mode > 0) {
          Serial.println("Preamble Sniff Trick is ON. Disable with 'a' to set manual address.");
          break;
        }
        Serial.println("Enter full address (Prefix + Base) as hex bytes, space separated:");
        Serial.println("e.g., AA 12 34 56 78 (for 5 bytes) or AA 12 34 (for 3 bytes)");
        entering_address = true;
        addr_entry = "";
        break;
      }

      case 'X': {
        if (currentState != LISTENING) { Serial.println("Not in LISTENING. Sweep first."); break; }
        run_prefix_scan();
        break;
      }
      case 'Y': {
        if (currentState != LISTENING) { Serial.println("Not in LISTENING. Sweep first."); break; }
        if (!have_prefix) { Serial.println("No prefix yet. Press 'X' first."); break; }
        uint8_t b;
        if (run_next_byte_scan(&b)) {}
        break;
      }

      case 'R': // Uppercase R for Record toggle
        if (currentState != LISTENING) {
          Serial.println("Must be in LISTENING mode to record.");
          break;
        }
        is_recording = !is_recording;
        if (is_recording) {
          Serial.print(">>> RECORDING ARMED. Clearing old packets. Max=");
          Serial.print(MAX_RECORDED_PACKETS);
          Serial.println(" packets.");
          recorded_packet_count = 0;
          memset(recorded_packets, 0, sizeof(recorded_packets));
          digitalWrite(LED_PIN, LOW); // LED on solid
        } else {
          Serial.print(">>> RECORDING STOPPED. Captured ");
          Serial.print(recorded_packet_count);
          Serial.println(" packets.");
          digitalWrite(LED_PIN, HIGH); // LED off
        }
        break;

      case 'f': // lowercase f for fire
        if (is_recording) {
          Serial.println("Cannot 'fire' while recording is active. Press 'R' to stop first.");
          break;
        }
        if (recorded_packet_count == 0) {
          Serial.println("No packets recorded. Press 'R' to start/stop recording first.");
          break;
        }
        Serial.print(">>> Firing ");
        Serial.print(recorded_packet_count);
        Serial.println(" recorded packets...");
        fire_recorded_packets();
        break;

      default:
        if (currentState != LISTENING) {
          if (c == 'c') {
            Serial.println("Enter channel number + Enter:"); chan_entry = ""; break;
          }
          if (isDigit(c)) {
            chan_entry = String(c); Serial.print(c); break;
          }
          Serial.println("Not in LISTENING yet. Press 'S' or D7 to sweep first.");
          break;
        }
        // --- Keys below only work when LISTENING ---
        switch (c) {
          case 'W':
            whitening_enabled = !whitening_enabled;
            apply_pcnf0_pcnf1();
            set_channel(best_ch_found);
            Serial.print("Whitening "); Serial.println(whitening_enabled ? "ENABLED" : "DISABLED");
            break;

          case 'e':
            payload_endian_little = !payload_endian_little;
            apply_pcnf0_pcnf1();
            set_channel(best_ch_found);
            Serial.print("Payload Endian set to: "); Serial.println(payload_endian_little ? "Little (nRF)" : "Big (BLE)");
            break;

          case 'D':
            current_mode = (current_mode == RADIO_MODE_MODE_Nrf_2Mbit)
                            ? RADIO_MODE_MODE_Nrf_1Mbit : RADIO_MODE_MODE_Nrf_2Mbit;
            NRF_RADIO->MODE = current_mode << RADIO_MODE_MODE_Pos;
            set_channel(best_ch_found);
            Serial.print("Data rate: "); Serial.println((current_mode == RADIO_MODE_MODE_Nrf_2Mbit) ? "2M" : "1M");
            break;

          case 'b':
            BALEN = (BALEN % 4) + 1;
            apply_pcnf0_pcnf1();
            set_channel(best_ch_found);
            Serial.print("BALEN="); Serial.println(BALEN);
            if (preamble_trick_mode > 0) { Serial.println(">>> (NOTE: BALEN is overridden by Preamble Trick)"); }
            break;

          case 'l':
            LFLEN = (LFLEN + 1) % 9;
            apply_pcnf0_pcnf1();
            Serial.print("LFLEN="); Serial.println(LFLEN);
            set_channel(best_ch_found);
            break;

          case 's':
            S1LEN = (S1LEN + 1) % 8;
            apply_pcnf0_pcnf1();
            Serial.print("S1LEN="); Serial.println(S1LEN);
            set_channel(best_ch_found);
            break;

          case 't':
            if (STATLEN == 0) STATLEN = 6;
            else if (STATLEN == 6) STATLEN = 8;
            else if (STATLEN == 8) STATLEN = 16;
            else if (STATLEN == 16) STATLEN = 24;
            else if (STATLEN == 24) STATLEN = 32;
            else if (STATLEN == 32) STATLEN = 64;
            else STATLEN = 0;
            apply_pcnf0_pcnf1();
            Serial.print("STATLEN="); Serial.println(STATLEN);
            set_channel(best_ch_found);
            break;

          case 'K':
            Serial.println("Enter exact STATLEN (0-255) then Enter:");
            entering_statlen = true;
            statlen_entry = "";
            set_channel(best_ch_found);
            break;

          case 'i':
            crc_skip_addr = !crc_skip_addr;
            configure_radio_for_state(LISTENING);
            Serial.print("CRC Skip Address set to: "); Serial.println(crc_skip_addr ? "Skip (Payload Only)" : "Include (Addr + Payload)");
            break;

          case 'V':
            crc_param_profile = (crc_param_profile + 1) % 4; // Cycle 0-3
            configure_radio_for_state(LISTENING);
            Serial.print("CRC Profile set to: ");
            switch (crc_param_profile) {
              case 0: Serial.println(F("0: Default (Poly:0x1021, Init:0xFFFF)")); break;
              case 1: Serial.println(F("1: Kermit (Poly:0x1021, Init:0x0000)")); break;
              case 2: Serial.println(F("2: Modbus (Poly:0x8005, Init:0xFFFF)")); break;
              case 3: Serial.println(F("3: ARC (Poly:0x8005, Init:0x0000)")); break;
            }
            break;

          case 'C':
            current_crc_len = (current_crc_len + 1) % 3; // 0 -> 1 -> 2 -> 0
            configure_radio_for_state(LISTENING);
            Serial.print("CRC set to: ");
            if (current_crc_len == 0)      Serial.println(F("DISABLED"));
            else if (current_crc_len == 1) Serial.println(F("1 Byte"));
            else if (current_crc_len == 2) Serial.println(F("2 Bytes"));
            break;

          case 'p':
            header_parse_enabled = !header_parse_enabled;
            Serial.print("Header parsing "); Serial.println(header_parse_enabled ? "ENABLED" : "DISABLED");
            break;

          case '+':
            if (best_ch_found < MAX_CH) { best_ch_found++; set_channel(best_ch_found); }
            Serial.print("Channel -> "); Serial.println(best_ch_found);
            break;

          case '-':
            if (best_ch_found > MIN_CH) { best_ch_found--; set_channel(best_ch_found); }
            Serial.print("Channel -> "); Serial.println(best_ch_found);
            break;

          case 'c':
            Serial.println("Enter channel number + Enter:"); chan_entry = ""; break;

          case 'r':
            Serial.println("Reapplying radio with current params...");
            configure_radio_for_state(LISTENING);
            break;

          case '<': // Shift LEFT
            bit_shift_amount = (bit_shift_amount - 1);
            if (bit_shift_amount < -7) bit_shift_amount = 7;
            Serial.print("Bit shift set to: "); Serial.println(bit_shift_amount);
            break;

          case '>': // Shift RIGHT
            bit_shift_amount = (bit_shift_amount + 1);
            if (bit_shift_amount > 7) bit_shift_amount = -7;
            Serial.print("Bit shift set to: "); Serial.println(bit_shift_amount);
            break;

          case 'a': // Preamble Trick
            preamble_trick_mode = (preamble_trick_mode + 1) % 5;
            Serial.print("Preamble Sniff Trick set to: ");
            switch (preamble_trick_mode) {
              case 0: Serial.println(F("OFF (Using Address Discovery)")); break;
              case 1: Serial.println(F("ON: 0xAA (1-byte)")); break;
              case 2: Serial.println(F("ON: 0x55 (1-byte)")); break;
              case 3: Serial.println(F("ON: 0xAAAA (2-byte)")); break;
              case 4: Serial.println(F("ON: 0x5555 (2-byte)")); break;
            }
            if (preamble_trick_mode > 0) {
              Serial.println(F(">>> NOTE: Address discovery/settings are now overridden."));
            } else {
              Serial.println(F(">>> NOTE: Reverting to discovered address."));
            }
            configure_radio_for_state(LISTENING);
            break;

          default:
            if (isDigit(c)) { chan_entry = String(c); Serial.print(c); }
            else { Serial.print("Unknown key: "); Serial.println(c); }
            break;
        }
        break;
    }
  }
}

// ---------------- Setup / Loop ----------------
void setup() {
  pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, HIGH); // HIGH = LED OFF
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  Serial.begin(SERIAL_BAUD);
  unsigned long t0 = millis();
  while (!Serial && millis() - t0 < 1500) {}

  Serial.println("\n--- nRF52840 Sniffer ---");

  Serial.println("\nInternal nRF52 (Sniffer) ready.");
  Serial.println("Press D7 or 'S' to sweep, or 'c'/'A' to set params.");
  print_help();

  radio_disable(); // Disable sniffer radio initially
  currentState = IDLE;
  locked = false;
}

bool btn_prev = false;
void loop() {
  // 1. Check for button press to start sweep
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

      currentState = SWEEPING;
      configure_radio_for_state(SWEEPING);
    }
  }
  btn_prev = btn;

  // 2. Process serial commands from user
  serial_commands();

  // 3. Run the sniffer state machine
  switch (currentState) {
    case IDLE:
      delay(1);
      break;

    case SWEEPING: {
      uint8_t found = sweep_once_find_best();
      currentState = ANALYZING;
      radio_disable();
      Serial.println("\n--- Sweep done ---");
      if (found) { Serial.print("Best channel: "); Serial.println(found); }
      else { Serial.println("No channel activity found."); }
      break;
    }

    case ANALYZING: {
      if (best_ch_found) {
        locked = true;
        configure_radio_for_state(LISTENING);
        Serial.print(">>> Locked to channel "); Serial.println(best_ch_found);
        currentState = LISTENING;
      } else {
        locked = false;
        currentState = IDLE;
        Serial.println(">>> Returning to IDLE. Press D7 or 'S' to sweep again.");
      }
      break;
    }

    case LISTENING:
      poll_radio_events(best_ch_found, /*allow_prints=*/true);
      break;
  }
}
