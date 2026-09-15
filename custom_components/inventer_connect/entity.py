"""Shared entity base for inVENTer Connect."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_ADDRESS_KEY, DOMAIN, MANUFACTURER
from .coordinator import InventerCoordinator


class InventerEntity(CoordinatorEntity[InventerCoordinator]):
    """Ties an entity to the controller device and its zone."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: InventerCoordinator, key: str) -> None:
        super().__init__(coordinator)
        address = coordinator.entry.data[CONF_ADDRESS_KEY]
        self._attr_unique_id = f"{address}_zone{coordinator.zone}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            connections={("bluetooth", address)},
            manufacturer=MANUFACTURER,
            name=coordinator.entry.title,
        )

    @property
    def zone_status(self):
        return self.coordinator.data
