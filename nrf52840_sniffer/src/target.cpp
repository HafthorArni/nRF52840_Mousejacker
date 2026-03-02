#include "shared.h"

// =============================================================================
//                          nRF24 TARGET TRANSMITTER
// =============================================================================

// Define the global radio object here
RF24 radio(RF24_CE_PIN, RF24_CSN_PIN);

static const uint8_t target_rf_address[5] = { 0xE7, 0xE7, 0xE7, 0xE7, 0xE7 };
static unsigned long last_tx_time = 0;
static uint8_t tx_counter = 0;

void configure_target_transmitter() {
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

void run_target_transmitter() {
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