"""Sensors for an inVENTer Connect zone."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    CONCENTRATION_PARTS_PER_BILLION,
    CONCENTRATION_PARTS_PER_MILLION,
    PERCENTAGE,
    EntityCategory,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import InventerConfigEntry
from .entity import InventerEntity
from .protocol import ZoneStatus


@dataclass(frozen=True, kw_only=True)
class InventerSensorDescription(SensorEntityDescription):
    """Adds the accessor that pulls the value out of a zone status."""

    value_fn: Callable[[ZoneStatus], float | int | None]
    available_fn: Callable[[ZoneStatus], bool] = lambda _status: True


SENSORS: tuple[InventerSensorDescription, ...] = (
    InventerSensorDescription(
        key="int_temperature",
        translation_key="indoor_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda status: status.int_temperature,
    ),
    InventerSensorDescription(
        key="int_humidity",
        translation_key="indoor_humidity",
        device_class=SensorDeviceClass.HUMIDITY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda status: status.int_humidity,
    ),
    InventerSensorDescription(
        key="ext_temperature",
        translation_key="outdoor_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda status: status.ext_temperature,
        available_fn=lambda status: status.ext_sensor_present,
    ),
    InventerSensorDescription(
        key="ext_humidity",
        translation_key="outdoor_humidity",
        device_class=SensorDeviceClass.HUMIDITY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda status: status.ext_humidity,
        available_fn=lambda status: status.ext_sensor_present,
    ),
    InventerSensorDescription(
        key="int_co2",
        translation_key="carbon_dioxide",
        device_class=SensorDeviceClass.CO2,
        native_unit_of_measurement=CONCENTRATION_PARTS_PER_MILLION,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda status: status.int_co2,
        available_fn=lambda status: status.co2_sensor_present,
    ),
    InventerSensorDescription(
        key="int_voc",
        translation_key="volatile_organic_compounds",
        device_class=SensorDeviceClass.VOLATILE_ORGANIC_COMPOUNDS_PARTS,
        native_unit_of_measurement=CONCENTRATION_PARTS_PER_BILLION,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda status: status.int_voc,
    ),
    InventerSensorDescription(
        key="fan_speed",
        translation_key="fan_speed",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda status: status.fan_speed,
    ),
    InventerSensorDescription(
        key="timer",
        translation_key="override_remaining",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda status: status.timer if status.timer_active else 0,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: InventerConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(InventerSensor(coordinator, description) for description in SENSORS)


class InventerSensor(InventerEntity, SensorEntity):
    """One measured value from a zone."""

    entity_description: InventerSensorDescription

    def __init__(self, coordinator, description: InventerSensorDescription) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def available(self) -> bool:
        status = self.zone_status
        if not super().available or status is None:
            return False
        return self.entity_description.available_fn(status)

    @property
    def native_value(self) -> float | int | None:
        status = self.zone_status
        return None if status is None else self.entity_description.value_fn(status)
