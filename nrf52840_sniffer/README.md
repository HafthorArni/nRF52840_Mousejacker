# nRF52840 Sniffer and Replay Tool

This is the PlatformIO project for the Adafruit Feather nRF52840 Express used
as a low-level 2.4 GHz sniffer and replay device.

It implements:

- Channel sweeping using RSSI.
- The "preamble trick" for promiscuous capture.
- Interactive serial UI for on-the-fly tuning of RADIO registers.
- Recording and replay of captured packets.

## Hardware overview

Feather nRF52840 sniffer with external nRF24L01+ module:

![Feather nRF52840 sniffer wiring](../graphics/sniffer_with_nrf24_bb.png)

## Boards / environment

- Board: `adafruit_feather_nrf52840`
- Framework: Arduino (Adafruit nRF52 core)

## Firmware variants

There are two variants of the Feather firmware:

- `src/main_sniffer_with_nrf24.cpp`  
  Default build. Sniffer firmware that assumes an external nRF24L01+ module is
  connected to the Feather (used for validation / loopback tests).

- `extras/main_sniffer_standalone.cpp`  
  Alternate version that runs the sniffer without any external nRF24 module
  attached. Use this if only the Feather nRF52840 itself is present.

PlatformIO only compiles source files in `src/`, so whichever variant lives in
`src/` will be the one that builds.

### Switching to the standalone sniffer (no nRF24 attached)

1. Move the current default firmware out of `src/`:

       mv src/main_sniffer_with_nrf24.cpp extras/main_sniffer_with_nrf24.cpp

2. Move the standalone variant into `src/`:

       mv extras/main_sniffer_standalone.cpp src/main_sniffer_standalone.cpp

3. Build and upload:

       pio run
       pio run -t upload

(You can also do these moves in the VSCode Explorer if you prefer GUI.)

## Building and uploading

From this folder (`nrf52840_sniffer`):

    pio run            # build
    pio run -t upload  # flash to the Feather nRF52840

## Serial interface (overview)

The firmware exposes an interactive interface over the USB serial port.
Typical usage is via:

    pio device monitor

at 250000 baud.

Example commands:
- `h` - for help
- `W` – toggle whitening (`PCNF1.WHITEEN`)
- `D` – toggle data rate (1 Mbps / 2 Mbps)
- `C` – cycle CRC length (off / 1 byte / 2 bytes)
- `b`, `l`, `s`, `t`, `K` – adjust `PCNF0` / `PCNF1` packet format fields
- `X` – run 1-byte prefix scan
- `Y` – run next-byte base address scan

