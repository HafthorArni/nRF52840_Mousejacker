#include <Arduino.h>
#include <SPI.h>
#include <nRF24L01.h>
#include <RF24.h>
#include <Adafruit_NeoPixel.h>

// NeoPixel
#define NEOPIXEL_PIN    40
#define NEOPIXEL_COUNT  1
Adafruit_NeoPixel strip(NEOPIXEL_COUNT, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);

// nRF24 (single radio)
#define NRF_CE_PIN  5
#define NRF_CSN_PIN 6

RF24 radio1(NRF_CE_PIN, NRF_CSN_PIN);  

// Payload / RF config
#define PAYLOAD_SIZE 32
const byte rf_channel = 55;
static const uint8_t pipeAddress[5] = { 0xE7, 0xE7, 0xE7, 0xE7, 0xE7 };
char txMessage[PAYLOAD_SIZE] = "METRO_ECHO_TEST_01";

// TX / RX state
const unsigned long txInterval = 500;
unsigned long lastTxTime = 0;
char rxMessage[PAYLOAD_SIZE] = {0};

// State machine
enum LedState {
  STATE_LOOKING_FOR_GREEN,
  STATE_IGNORING_GREEN,
  STATE_LOOKING_FOR_BLUE,
  STATE_IGNORING_BLUE
};
LedState currentState = STATE_LOOKING_FOR_GREEN;
const unsigned long ignoreDuration = 5000;
unsigned long ignoreTimerStart = 0;

// TX helper
void transmitPacket() {
  radio1.stopListening();
  Serial.print("Radio 1 TX: ");
  Serial.println(txMessage);
  bool report = radio1.write(&txMessage, PAYLOAD_SIZE);
  radio1.txStandBy();
  radio1.startListening();

  if (!report) {
    Serial.println("Radio 1 TX Failed (FIFO was full).");
  }
}

// LED helpers
void setLedGreen() {
  strip.setPixelColor(0, strip.Color(0, 255, 0)); // solid green
  strip.show();
}

void setLedPulseBlue(unsigned long now) {
  float brightness = (exp(sin(now / 2000.0 * PI)) - 0.36787944) * 108.0;
  strip.setPixelColor(0, strip.Color(0, 0, (int)brightness)); // pulsing blue
  strip.show();
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 2000) {}
  Serial.println("Metro M4 nRF24 Echo Test (1 Radio)");

  strip.begin();
  strip.setBrightness(20);
  strip.setPixelColor(0, strip.Color(0, 0, 50)); // blue = init
  strip.show();

  Serial.println("Waiting for nRF24 module to stabilize (250ms)...");
  delay(1000);

  Serial.println("Initializing Radio 1 (D5, D6)...");
  if (!radio1.begin()) {
    Serial.println("Radio 1 not found. Check wiring.");
    strip.setPixelColor(0, strip.Color(255, 0, 0)); // red = error
    strip.show();
    delay(1000);
    while (1);
  }

  radio1.setChannel(rf_channel);
  radio1.setDataRate(RF24_1MBPS);
  radio1.setPALevel(RF24_PA_MAX);
  radio1.setAddressWidth(5);
  radio1.setCRCLength(RF24_CRC_16);
  radio1.setPayloadSize(PAYLOAD_SIZE);
  radio1.setAutoAck(false);
  radio1.setRetries(0, 0);
  radio1.openWritingPipe(pipeAddress);
  radio1.openReadingPipe(1, pipeAddress);
  radio1.startListening();
  Serial.println("Radio 1 initialized.");

  Serial.println("Setup complete. STATE: LOOKING_FOR_GREEN");
}

void loop() {
  unsigned long now = millis();
  bool signalAvailable = radio1.available();

  switch (currentState) {

    case STATE_LOOKING_FOR_GREEN:
      setLedPulseBlue(now);
      if (now - lastTxTime >= txInterval) {
        lastTxTime = now;
        transmitPacket();
      }
      if (signalAvailable) {
        radio1.read(&rxMessage, PAYLOAD_SIZE);
        Serial.print("R1 RX (Green): "); Serial.println(rxMessage);
        if (strcmp(txMessage, rxMessage) == 0) {
          Serial.println("R1 Signal DETECTED. -> STATE: IGNORING_GREEN");
          currentState = STATE_IGNORING_GREEN;
          ignoreTimerStart = now;
          setLedGreen();
        }
      }
      break;

    case STATE_IGNORING_GREEN:
      setLedGreen();
      if (signalAvailable) {
        radio1.read(&rxMessage, PAYLOAD_SIZE);
        Serial.println("R1 Ignoring RX (Green)");
      }
      if (now - ignoreTimerStart >= ignoreDuration) {
        Serial.println("Green ignore ended. -> STATE: LOOKING_FOR_BLUE");
        currentState = STATE_LOOKING_FOR_BLUE;
        lastTxTime = now;
      }
      break;

    case STATE_LOOKING_FOR_BLUE:
      setLedGreen();
      if (now - lastTxTime >= txInterval) {
        lastTxTime = now;
        transmitPacket();
      }
      if (signalAvailable) {
        radio1.read(&rxMessage, PAYLOAD_SIZE);
        Serial.print("R1 RX (Blue): "); Serial.println(rxMessage);
        if (strcmp(txMessage, rxMessage) == 0) {
          Serial.println("R1 Signal DETECTED. -> STATE: IGNORING_BLUE");
          currentState = STATE_IGNORING_BLUE;
          ignoreTimerStart = now;
          setLedPulseBlue(now);
        }
      }
      break;

    case STATE_IGNORING_BLUE:
      setLedPulseBlue(now);
      if (signalAvailable) {
        radio1.read(&rxMessage, PAYLOAD_SIZE);
        Serial.println("R1 Ignoring RX (Blue)");
      }
      if (now - ignoreTimerStart >= ignoreDuration) {
        Serial.println("Blue ignore period ended. -> STATE: LOOKING_FOR_GREEN");
        currentState = STATE_LOOKING_FOR_GREEN;
        lastTxTime = now;
      }
      break;
  }
}
