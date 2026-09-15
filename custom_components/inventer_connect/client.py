"""BLE transport for an inVENTer Connect controller.

Speaks the packet protocol in protocol.py over the controller's single
transport characteristic. Connections are routed by Home Assistant's Bluetooth
stack, so an ESPHome Bluetooth proxy near the controller works transparently.

The channel is polled, not notified: after writing a request the client reads
the characteristic, acknowledges each fragment by writing its index back, and
reads again until the fragment counter says the packet is complete.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from . import protocol
from .const import (
    FIRMWARE_REVISION_CHARACTERISTIC,
    HARDWARE_REVISION_CHARACTERISTIC,
    MANUFACTURER_NAME_CHARACTERISTIC,
    MODEL_NUMBER_CHARACTERISTIC,
    PIN_CODE_CHARACTERISTIC,
    PIN_CONFIRMATION_CHARACTERISTIC,
    SERIAL_NUMBER_CHARACTERISTIC,
    TRANSPORT_CHARACTERISTIC,
)

_LOGGER = logging.getLogger(__name__)

#: The app waits this long before its first read of a transaction.
FIRST_READ_DELAY = 0.1

#: Guard against a controller that never raises the last-fragment flag.
MAX_FRAGMENTS = 16

DEVICE_INFO_CHARACTERISTICS = {
    "manufacturer": MANUFACTURER_NAME_CHARACTERISTIC,
    "model": MODEL_NUMBER_CHARACTERISTIC,
    "serial_number": SERIAL_NUMBER_CHARACTERISTIC,
    "firmware_revision": FIRMWARE_REVISION_CHARACTERISTIC,
    "hardware_revision": HARDWARE_REVISION_CHARACTERISTIC,
}


class InventerError(Exception):
    """Base error for controller communication."""


class InventerProtocolError(InventerError):
    """The controller answered with something we cannot parse."""


class InventerAuthError(InventerError):
    """The controller rejected the PIN."""


class InventerConnectionError(InventerError):
    """The controller could not be reached."""


class InventerClient:
    """One controller, addressed over BLE."""

    def __init__(self, device_lookup: Callable[[], BLEDevice | None], pin: int,
                 *, keep_connected: bool = False) -> None:
        self._device_lookup = device_lookup
        self._pin = pin
        self._keep_connected = keep_connected
        self._client: BleakClientWithServiceCache | None = None
        self._authenticated = False
        self._lock = asyncio.Lock()

    # --- connection ---------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    async def _ensure_connected(self) -> BleakClientWithServiceCache:
        if self.connected:
            assert self._client is not None
            return self._client

        device = self._device_lookup()
        if device is None:
            raise InventerConnectionError(
                "controller not currently visible to any Bluetooth adapter or proxy")

        try:
            self._client = await establish_connection(
                BleakClientWithServiceCache,
                device,
                device.address,
                ble_device_callback=self._device_lookup,
            )
        except (BleakError, asyncio.TimeoutError) as err:
            raise InventerConnectionError(f"could not connect to controller: {err}") from err

        self._authenticated = False
        await self._authenticate()
        return self._client

    async def _authenticate(self) -> None:
        """Write the PIN and check the controller's confirmation."""
        client = self._client
        assert client is not None

        if client.services.get_characteristic(TRANSPORT_CHARACTERISTIC) is None:
            raise InventerError(
                "device does not expose the inVENTer transport characteristic")

        try:
            # 4-byte little-endian int, matching both the app and pycalima.
            # Masked rather than signed so an out-of-range value cannot raise
            # OverflowError here instead of being rejected by the controller.
            await client.write_gatt_char(
                PIN_CODE_CHARACTERISTIC, (self._pin & 0xFFFFFFFF).to_bytes(4, "little"),
                response=True)
            confirmation = await client.read_gatt_char(PIN_CONFIRMATION_CHARACTERISTIC)
        except BleakError as err:
            raise InventerAuthError(f"PIN handshake failed: {err}") from err

        if not any(confirmation):
            raise InventerAuthError("controller rejected the PIN")

        self._authenticated = True
        _LOGGER.debug("Authenticated against %s", client.address)

    async def disconnect(self) -> None:
        client, self._client = self._client, None
        self._authenticated = False
        if client is not None and client.is_connected:
            try:
                await client.disconnect()
            except BleakError as err:
                _LOGGER.debug("Ignoring error while disconnecting: %s", err)

    async def _release(self) -> None:
        """Drop the link unless the user asked us to hold it.

        Holding it keeps the phone app locked out, so the default is to let go
        between polls.
        """
        if not self._keep_connected:
            await self.disconnect()

    # --- transactions -------------------------------------------------------

    async def _write_frames(self, client: BleakClientWithServiceCache,
                            packet: bytes, ack: int) -> None:
        for frame in protocol.fragment(packet, ack=ack):
            await client.write_gatt_char(TRANSPORT_CHARACTERISTIC, frame, response=True)

    async def _read_packet(self, client: BleakClientWithServiceCache) -> bytes:
        """Poll the transport characteristic until a full packet arrives."""
        reassembler = protocol.Reassembler()
        await asyncio.sleep(FIRST_READ_DELAY)

        for _ in range(MAX_FRAGMENTS):
            frame = bytes(await client.read_gatt_char(TRANSPORT_CHARACTERISTIC))
            complete = reassembler.push(frame)
            await client.write_gatt_char(
                TRANSPORT_CHARACTERISTIC, protocol.ack_frame(reassembler.received),
                response=True)
            if complete:
                return reassembler.packet()

        await client.write_gatt_char(
            TRANSPORT_CHARACTERISTIC, protocol.cancel_frame(), response=True)
        raise InventerError("controller never finished the packet")

    async def async_send(self, packet: bytes, ack: int = 0) -> None:
        """Send a command and do not wait for a reply."""
        async with self._lock:
            client = await self._ensure_connected()
            try:
                await self._write_frames(client, packet, ack)
            except BleakError as err:
                await self.disconnect()
                raise InventerConnectionError(f"write failed: {err}") from err
            except protocol.ProtocolError as err:
                raise InventerProtocolError(str(err)) from err
            finally:
                await self._release()

    async def async_request(self, packet: bytes, expected_type: int, ack: int = 0) -> bytes:
        """Send a request and return the reassembled response packet."""
        async with self._lock:
            client = await self._ensure_connected()
            try:
                await self._write_frames(client, packet, ack)
                response = await self._read_packet(client)
            except (BleakError, asyncio.TimeoutError) as err:
                await self.disconnect()
                raise InventerConnectionError(f"request failed: {err}") from err
            except protocol.ProtocolError as err:
                # A garbled reply leaves the channel mid-transfer; abandon the
                # link so the next poll starts from a known state.
                await self.disconnect()
                raise InventerProtocolError(str(err)) from err
            finally:
                await self._release()

        actual = protocol.packet_type(response)
        if actual != expected_type:
            raise InventerProtocolError(
                f"expected packet type {expected_type}, controller answered with {actual}")
        return response

    # --- high level ---------------------------------------------------------

    async def async_read_zone(self, zone: int) -> protocol.ZoneStatus:
        response = await self.async_request(
            protocol.request_zone_row(zone), protocol.TYPE_ZONE_VIEW_ROW)
        try:
            return protocol.parse_zone_row(response)
        except protocol.ProtocolError as err:
            raise InventerProtocolError(str(err)) from err

    async def async_set_speed(self, zone: int, speed: int, mode: int, timeout_sec: int) -> None:
        await self.async_send(protocol.set_zone_speed(zone, speed, mode, timeout_sec))

    async def async_boost(self, zone: int) -> None:
        await self.async_send(protocol.zone_boost(zone))

    async def async_pause(self, zone: int) -> None:
        await self.async_send(protocol.zone_pause(zone))

    async def async_cancel(self, zone: int) -> None:
        await self.async_send(protocol.cancel(zone))

    async def async_device_info(self) -> dict[str, str]:
        """Read the GATT device-information strings, skipping any that fail."""
        async with self._lock:
            client = await self._ensure_connected()
            info: dict[str, str] = {}
            try:
                for key, uuid in DEVICE_INFO_CHARACTERISTICS.items():
                    try:
                        raw = await client.read_gatt_char(uuid)
                    except BleakError:
                        continue
                    info[key] = raw.decode("utf-8", "replace").strip("\x00").strip()
            finally:
                await self._release()
        return info


async def async_probe(device: BLEDevice, pin: int) -> dict[str, str]:
    """Connect once to verify PIN and compatibility; used by the config flow."""
    client = InventerClient(lambda: device, pin)
    try:
        return await client.async_device_info()
    finally:
        await client.disconnect()


__all__ = [
    "InventerClient",
    "InventerError",
    "InventerAuthError",
    "InventerProtocolError",
    "InventerConnectionError",
    "async_probe",
]
