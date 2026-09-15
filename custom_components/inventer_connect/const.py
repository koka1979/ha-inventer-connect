"""Constants for the inVENTer Connect integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "inventer_connect"

#: Key of the BLE address inside the config entry (homeassistant.const.CONF_ADDRESS).
CONF_ADDRESS_KEY: Final = "address"
CONF_PIN: Final = "pin"
CONF_ZONE: Final = "zone"
CONF_KEEP_CONNECTED: Final = "keep_connected"

DEFAULT_ZONE: Final = 0
DEFAULT_SCAN_INTERVAL: Final = 60
DEFAULT_BOOST_HOURS: Final = 1

#: Packet transport on the controller. Its presence is what identifies a
#: compatible device during discovery.
TRANSPORT_CHARACTERISTIC: Final = "e6ec2fd8-e888-4eb2-9681-e78ed6ea89e1"

CONNECTION_SERVICE: Final = "e6834e4b-7b3a-48e6-91e4-f1d005f564d3"
PIN_CODE_CHARACTERISTIC: Final = "4cad343a-209a-40b7-b911-4d9b3df569b2"
PIN_CONFIRMATION_CHARACTERISTIC: Final = "d1ae6b70-ee12-4f6d-b166-d2063dcaffe1"

HARDWARE_REVISION_CHARACTERISTIC: Final = "00002a27-0000-1000-8000-00805f9b34fb"
FIRMWARE_REVISION_CHARACTERISTIC: Final = "00002a26-0000-1000-8000-00805f9b34fb"
MODEL_NUMBER_CHARACTERISTIC: Final = "00002a24-0000-1000-8000-00805f9b34fb"
SERIAL_NUMBER_CHARACTERISTIC: Final = "00002a25-0000-1000-8000-00805f9b34fb"
MANUFACTURER_NAME_CHARACTERISTIC: Final = "00002a29-0000-1000-8000-00805f9b34fb"

MANUFACTURER: Final = "inVENTer"
