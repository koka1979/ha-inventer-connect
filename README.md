# inVENTer Connect for Home Assistant

Local control of an inVENTer Connect ventilation controller over Bluetooth LE.
No cloud and no vendor account: this speaks the same protocol the inVENTer
Mobile app speaks, directly to the controller on your own network.

> **Status: unproven on hardware.** The protocol layer is covered by tests that
> run without a device, but no part of this has yet talked to a real controller.
> Treat the first setup as an experiment, not an install.

## What it talks to

The **controller**, not the individual ventilation units. The controller keeps
its own 868 MHz network to the inner dampers, so this integration takes the
app's place towards the controller and leaves the radio side untouched.

Intended for Basic Connect e4/e8 and easy connect e16 **without** WiFi.
Controllers with WiFi expose the same packet protocol over TLS-PSK on TCP
47820, which is documented in [`docs/protocol.md`](docs/protocol.md) but not
implemented here.

## Related work

For standalone fans on the Pax per-characteristic GATT profile — Pax Calima and
Levante, Vent-Axia Svara and Svensa, and reportedly the inVENTer Pulsar — use
[`eriknn/ha-pax_ble`](https://github.com/eriknn/ha-pax_ble) instead. It is
mature, installable through HACS and covers those devices properly.

This project exists for the case that one does not cover: the Connect
controller, which speaks a packet protocol over a single characteristic rather
than the Pax profile. As of September 2026 nothing published handles it — the
[forum thread asking for it](https://community.home-assistant.io/t/looking-for-inventer-easy-control-e16-ha-integration/857319)
has run since 2025 without a solution.

## Requirements

- The controller in range of a Bluetooth adapter or an **ESPHome Bluetooth
  proxy with active connections** enabled.
- The PIN printed in the controller's manual.

## Installation

**HACS** — add this repository as a custom repository of category
*Integration*, download it, restart Home Assistant. Discovered controllers then
appear under Settings → Devices & Services; otherwise add *inVENTer Connect*
manually and pick the device.

**Manually** — copy `custom_components/inventer_connect` into your Home
Assistant `config/custom_components/` directory and restart.

## Entities

| Entity | Notes |
|---|---|
| `fan` | Speed 1–4, preset modes `auto`, `boost`, `pause` |
| `sensor` | Indoor/outdoor temperature and humidity, CO2, VOC, fan speed, override remaining |
| `binary_sensor` | Boost active, pause active, timer active, global command active |

Outdoor and CO2 sensors report unavailable unless the zone's status flags say
the matching sensor is fitted.

`auto` cancels any override and hands the zone back to its programmed
ventilation profile. Setting a speed sends an override with a timeout of two
poll intervals, so the zone returns to its profile by itself if Home Assistant
stops talking to it.

## Connection handling

By default the link is dropped between polls, because the controller is not
expected to serve the phone app and Home Assistant at the same time. The *Hold
the Bluetooth connection open* option trades that back for faster commands.

Whether the controller accepts concurrent connections at all is untested — if
the inVENTer app stops connecting while this integration runs, that is why.

## How it works

The controller exposes a single packet-transport characteristic rather than one
characteristic per function. Frames are 20 bytes, fragmented by hand, polled
rather than notified, and carry a CRC-8 variant that tests the MSB *after*
shifting — build it the textbook way and the firmware rejects every packet.

The full analysis, including the zone-status layout and the WiFi path, is in
[`docs/protocol.md`](docs/protocol.md). `tools/` holds a read-only BLE probe and
an MDSDP discovery probe.

## Status and known gaps

The command path is derived from the app's own request builders and is well
understood. The status path decodes the zone row at the offsets the app uses,
but several bytes in that row are still unidentified, and the meaning of the
ventilation-mode values is unknown.

If something reads wrong, the integration's **diagnostics download** includes
the raw zone-row packet as hex — that is what the remaining fields can be
mapped from.

## Development

The protocol layer has no Home Assistant or Bluetooth imports and is tested
standalone:

```bash
python3 -m pytest tests/test_protocol.py
```

## Licence and provenance

Apache 2.0. The protocol was recovered from the inVENTer Mobile Android app for
the purpose of interoperability with hardware the author owns, which in the EU
is covered by Article 6 of Directive 2009/24/EC (in Germany, § 69e UrhG). No
decompiled code or vendor binaries are included in this repository — only
protocol observations.

Not affiliated with or endorsed by inVENTer GmbH or the Volution Group.
