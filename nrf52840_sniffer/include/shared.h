#ifndef SHARED_H
#define SHARED_H

#include <Arduino.h>
#include <RF24.h>

// =============================================================================
//                              CONSTANTS & CONFIG
// =============================================================================

#define SERIAL_BAUD       250000
#define LED_PIN           LED_BUILTIN
#define BUTTON_PIN        7

// Radio Hardware
#define RF24_CE_PIN       9
#define RF24_CSN_PIN      10

// Sweep Settings
#define MIN_CH            2      // 2402 MHz
#define MAX_CH            80     // 2480 MHz
#define DWELL_MS          100    // per-channel dwell

// Buffer Sizes
#define RADIO_MAX_PAYLOAD 62
#define MAX_PDU_SIZE      64 // (sizeof(esb_rx_t)) - simplified for shared
#define MAX_RECORDED_PACKETS 50
#define MAX_RECORDED_PAYLOAD 64

// Target Config
#define TARGET_RF_CHANNEL         50
#define TARGET_RADIO_PAYLOAD_SIZE 32

// =============================================================================
//                                DATA TYPES
// =============================================================================

enum State { IDLE, SWEEPING, ANALYZING, LISTENING };

typedef struct __attribute__((packed)) {
  uint8_t LENGTH;
  uint8_t S1;
  uint8_t payload[RADIO_MAX_PAYLOAD];
} esb_rx_t;

struct AddressPreset {
    const char* name;
    bool raw_mode;
    uint8_t base0[4];
    uint8_t base1[4];
    uint8_t prefixes[8];
};

typedef struct {
  uint8_t len;
  uint8_t data[MAX_RECORDED_PAYLOAD];
  uint32_t timestamp_ms;
} RecordedPacket;

// =============================================================================
//                             GLOBAL EXTERNS
// =============================================================================

// -- Hardware Objects --
extern RF24 radio;

// -- State Machine --
extern volatile State currentState;
extern bool locked;

// -- Radio Parameters --
extern uint8_t  best_ch_found;
extern bool     whitening_enabled;
extern uint32_t current_mode;
extern uint8_t  BALEN;
extern uint8_t  LFLEN;
extern uint8_t  S1LEN;
extern uint8_t  STATLEN;
extern uint8_t  current_crc_len;
extern bool     header_parse_enabled;
extern bool     payload_endian_little;
extern uint8_t  crc_param_profile;
extern bool     crc_skip_addr;
extern int8_t   bit_shift_amount;
extern uint8_t  current_plen_mode;
extern int8_t   focused_pipe_idx;

// -- Discovery / Presets --
extern bool     use_preset_mode;
extern const AddressPreset* PRESETS[];
extern const uint8_t NUM_PRESETS;
extern uint8_t  current_preset_idx;
extern bool     have_prefix;
extern uint8_t  discovered_prefix;
extern uint8_t  discovered_base[4];
extern uint8_t  discovered_count;

// -- Recording / UI --
extern bool     clean_output_mode;
extern bool     is_recording;
extern uint16_t recorded_packet_count;
extern RecordedPacket recorded_packets[];
extern int8_t   PRINT_RSSI_THRESH;

// =============================================================================
//                           FUNCTION PROTOTYPES
// =============================================================================

// Defined in src/main.cpp
void configure_radio_for_state(State s);
void set_channel(uint8_t ch);
void apply_pcnf0_pcnf1();
void radio_base_config();
void discovery_reset_all();
void discovery_undo_last_byte();
bool run_prefix_scan();
bool run_next_byte_scan(uint8_t *found_byte);
void fire_recorded_packets();
void set_manual_address(String s);

// Defined in src/target.cpp
void configure_target_transmitter();
void run_target_transmitter();

// Defined in src/ui.cpp
void print_params();
void print_help();
void serial_commands();
void print_byte(uint8_t b);
void print_hex(const uint8_t* b, size_t n);
void print_ts();

#endif