#include <Arduino.h>
#include <SPI.h>
#include <nRF24L01.h>
#include <RF24.h>
#include <Adafruit_NeoPixel.h>

// NeoPixel
#define NEOPIXEL_PIN    40
#define NEOPIXEL_COUNT  1
Adafruit_NeoPixel strip(NEOPIXEL_COUNT, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);

// nRF24 pins
#define NRF1_CE_PIN  5
#define NRF1_CSN_PIN 6
#define NRF2_CE_PIN  4
#define NRF2_CSN_PIN 3

// Button
#define BUTTON_PIN 10

// Two radios + active pointer (8 MHz SPI)
RF24 radio1(NRF1_CE_PIN, NRF1_CSN_PIN, 8000000);
RF24 radio2(NRF2_CE_PIN, NRF2_CSN_PIN, 8000000);
RF24* activeRadio;

// Payload / RF config
#define PAYLOAD_SIZE 32
const byte rf_channel = 55;
static const uint8_t pipeAddress[5] = { 0xE7, 0xE7, 0xE7, 0xE7, 0xE7 };
char txMessage[PAYLOAD_SIZE] = "METRO_ECHO_TEST_01";

// TX / echo state
const unsigned long txInterval = 500;
unsigned long lastTxTime = 0;
bool echoReceived = false;

// Button debounce / radio toggle state
bool radio2IsActive = false;
int stableButtonState = HIGH;
int lastReadingState = HIGH;
unsigned long lastDebounceTime = 0;
const unsigned long debounceDelay = 50;

// Configure a single nRF24
void configureRadio(RF24& radio, const char* radioName) {
  if (!radio.begin()) {
    Serial.print("nRF24 ");
    Serial.print(radioName);
    Serial.println(" not found. Check wiring.");
    strip.setPixelColor(0, strip.Color(255, 0, 0)); // red = error
    strip.show();
    while (1);
  }

  radio.setChannel(rf_channel);
  radio.setDataRate(RF24_1MBPS);
  radio.setPALevel(RF24_PA_MAX);
  radio.setAddressWidth(5);
  radio.setCRCLength(RF24_CRC_16);
  radio.setPayloadSize(PAYLOAD_SIZE);
  radio.setAutoAck(false);
  radio.setRetries(0, 0);

  radio.openWritingPipe(pipeAddress);
  radio.openReadingPipe(1, pipeAddress);
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
  Serial.println("Metro M4 nRF24 Dual Radio Echo Test (Toggle Mode)");

  strip.begin();
  strip.setBrightness(20);
  strip.setPixelColor(0, strip.Color(0, 0, 50)); // blue = init
  strip.show();

  pinMode(BUTTON_PIN, INPUT_PULLUP);
  lastReadingState = digitalRead(BUTTON_PIN);
  stableButtonState = lastReadingState;
  Serial.println("Button on D10 initialized (INPUT_PULLUP).");

  Serial.println("Waiting for nRF24 modules to stabilize...");
  delay(250);

  configureRadio(radio1, "Radio 1 (D5/D6)");
  configureRadio(radio2, "Radio 2 (D4/D3)");
  Serial.println("Both radios configured.");

  // Start in RX mode based on initial button state
  if (stableButtonState == LOW) {
    activeRadio = &radio2;
    radio2IsActive = true;
    radio2.startListening();
    radio1.stopListening();
    Serial.println("Radio 2 (D4/D3) is active. Listening...");
  } else {
    activeRadio = &radio1;
    radio2IsActive = false;
    radio1.startListening();
    radio2.stopListening();
    Serial.println("Radio 1 (D5/D6) is active. Listening...");
  }
}

void loop() {
  unsigned long now = millis();

  // Debounced button read
  int currentReading = digitalRead(BUTTON_PIN);

  if (currentReading != lastReadingState) {
    lastDebounceTime = now;
  }

  if ((now - lastDebounceTime) > debounceDelay) {
    if (currentReading != stableButtonState) {
      stableButtonState = currentReading;

      // Toggle on press (HIGH -> LOW)
      if (stableButtonState == LOW) {
        radio2IsActive = !radio2IsActive;

        Serial.print("Button press detected. Toggling radio to: ");
        Serial.println(radio2IsActive ? "Radio 2 (D4/D3)" : "Radio 1 (D5/D6)");

        activeRadio->stopListening();

        activeRadio = radio2IsActive ? &radio2 : &radio1;
        activeRadio->startListening();

        echoReceived = false;
        lastTxTime = now;
      }
    }
  }

  lastReadingState = currentReading;

  // TX from active radio
  if (now - lastTxTime >= txInterval && !echoReceived) {
    lastTxTime = now;
    activeRadio->stopListening();

    Serial.print("Transmitting 32-bytes: ");
    Serial.println(txMessage);

    bool report = activeRadio->write(&txMessage, PAYLOAD_SIZE);
    activeRadio->txStandBy();
    activeRadio->startListening();

    if (!report) {
      Serial.println("TX Failed (FIFO was full).");
    }
  }

  // RX on active radio
  if (activeRadio->available()) {
    char rxMessage[PAYLOAD_SIZE] = {0};
    activeRadio->read(&rxMessage, PAYLOAD_SIZE);

    Serial.print("Received 32-bytes: ");
    Serial.println(rxMessage);

    if (strcmp(txMessage, rxMessage) == 0) {
      Serial.println("!!! ECHO DETECTED !!!");
      echoReceived = true;
    }
  }

  // LED status
  if (echoReceived) {
    setLedGreen();
  } else {
    setLedPulseBlue(now);
  }
}
