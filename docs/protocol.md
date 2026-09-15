# inVENTer Mobile — Reverse Engineering für Home Assistant

Analyse der Android-App `de.inventer.mobile` (Version 5.0.1, `versionCode` 50000001,
MD5 `cc06c0f3d8a677051807e5ce9a559f57`, signiert `CN=inventer, O=inventer, C=de`)
mit dem Ziel, einen inVENTer-Lüfter aus Home Assistant zu steuern.

Zielhardware in diesem Haushalt: **inVENTer Connect mit Regler ohne WLAN**
(Basic Connect e4/e8 oder easy connect e16). Damit ist Weg B unten der relevante Pfad.
Die PIN steht in der Anleitung des Reglers.

Zweck ist Interoperabilität mit selbst betriebener Hardware. In der EU ist die
Dekompilierung dafür durch Art. 6 der Software-Richtlinie 2009/24/EG bzw. § 69e UrhG
gedeckt. Es werden keine Binaries oder dekompilierten Quellen in dieses Repository
übernommen — nur Protokollbeobachtungen.

## Stand der Technik (Recherche September 2026)

Vor und nach dieser Arbeit geprüft, was es bereits gibt:

**Für eigenständige Lüfter mit Pax-Profil gibt es eine ausgereifte Lösung.**
[`eriknn/ha-pax_ble`](https://github.com/eriknn/ha-pax_ble) ("Pax & Vent-Axia
Bluetooth") deckt Pax Calima, Pax Levante 50, Vent-Axia Svara und Svensa ab, mit
Auto-Discovery und HACS-Installation. Unterbau ist
[`PatrickE94/pycalima`](https://github.com/PatrickE94/pycalima). Ein Nutzer
berichtet im HA-Forum, dass sich auch die **inVENTer Pulsar** damit einbinden
lässt — plausibel, denn Pulsar ist ein Einzelgerät mit genau diesem Profil.
Das ältere `MarkoMarjamaa/homeassistant-paxcalima` ist seit HA 2022.7 defekt.

**Für den Connect-Regler gibt es nichts.** Der einschlägige Forumsthread
[„Looking for InVENTer easy control e16 HA integration"](https://community.home-assistant.io/t/looking-for-inventer-easy-control-e16-ha-integration/857319)
läuft seit 2025 ohne Lösung; der jüngste Beitrag (August 2026) nennt einen
Anfänger, der an einer Integration für die **WiFi**-Variante arbeitet. Für den
BLE-Pfad des Reglers ist nichts veröffentlicht. Genau diese Lücke füllt die
Integration in diesem Repository.

**Für sMove gibt es den 0-10-V-Weg.** Dokumentiert als
[Community-Projekt](https://community.home-assistant.io/t/controlling-an-inventer-smove-decentralized-ventilation-system-via-ha-and-shelly/796906)
mit einem Shelly Dimmer 0/1-10V PM Gen3.

### Gegenprobe der Extraktion

`pycalima` ist eine unabhängige Reverse-Engineering-Arbeit am selben
Volution-Profil. Alle Characteristic-UUIDs, die dort dokumentiert sind, stimmen
mit der hier aus dem APK extrahierten Tabelle überein, ebenso das PIN-Format
(4 Byte Integer, little-endian, auf `4cad343a-…`). Das bestätigt den
Pax-Profil-Teil dieser Analyse von außen. Der Zirconia-Paketkanal des Reglers
kommt in `pycalima` nicht vor — er ist der neue Teil.

### Naheliegender nächster Schritt

Die saubere Heimat für diese Arbeit wäre ein Upstream-Beitrag zu `ha-pax_ble`:
das Projekt deckt die Pax-Familie bereits ab, und der Connect-Regler wäre eine
weitere Gerätefamilie darin statt einer konkurrierenden Integration.

## Ergebnis in einem Satz

Machbar, und deutlich besser als erwartet: die App spricht **ausschließlich lokal**
(kein Cloud-Backend, keine einzige Hersteller-URL im Bytecode), und die relevante
SDK-Schicht liegt **unobfuskiert** im APK.

## Aufbau der App

Die App ist nativ (Kotlin/Java, Realm als lokale DB), kein Flutter/RN. Der Anwendungscode
unter `de.inventer.mobile` ist per R8 obfuskiert, aber die gesamte Geräteanbindung liegt
unobfuskiert in `com.volution.wrapper.acdeviceconnection` (369 Klassen). inVENTer gehört
zur Volution Group, die dasselbe SDK für mehrere Marken verwendet — deshalb enthält das
APK Gerätefamilien, die mit inVENTer nichts zu tun haben.

Mitgelieferte Firmware-Images unter `assets/` benennen die Zielsysteme:
`FCU_Update.bin` (Fan Control Unit), `MZCU_Update.bin` (Multi-Zone Control Unit),
`Sensors_Update.bin`, `mev_update.bin`.

Gerätefamilien im SDK: `Calima`, `Momento`, `Sky`, `Magna`, `Mev`, `XFLP`, `Hyper`,
`Zirconia`. Für inVENTer Connect ist **Zirconia** die relevante Familie (Beleg:
`ZirconiaRequestWiFiModeWrite`, Zonen- und MEV-Kommandos, Multi-Zonen-Begriffe passend
zu MZCU). Die Zuordnung Zirconia ↔ inVENTer-Connect-Regler ist aus Funktionsumfang
und Firmware-Assets erschlossen, nicht aus einem expliziten Namens-String — sie ist
am realen Gerät zu bestätigen.

Wichtig für das Systemverständnis: die App redet **immer mit dem Regler**, nie direkt
mit einer Innenblende. Der Regler hält das eigene 868-MHz-Funknetz zu den Blenden.
Eine HA-Integration ersetzt also die App gegenüber dem Regler — die Funkstrecke
dahinter bleibt unangetastet.

## Das Zirconia-Paketformat (gilt für BLE und WLAN gleichermaßen)

Beide Transportwege tragen dasselbe Anwendungspaket. Aufbau, `preparePacket()`:

| Offset | Größe | Feld |
|---|---|---|
| 0 | 1 | Prüfsumme über Byte 1..`packetSize-1` |
| 1 | 1 | `packetSize` = Payload-Länge + 10 |
| 2 | 1 | Backtracking-Count (beim Senden 0) |
| 3 | 1 | Pakettyp (`STD_TYPE_*`-Ordinal) |
| 4 | 1 | Operationstyp: `1` = data update, `2` = data request |
| 5 | 1 | Zieladresse: `0` = Regler, `159` = ESP32-Modul |
| 6 | 4 | Zeitstempel, Sekunden seit `2000-01-01 00:00:00`, **big-endian** |
| 10 | n | Payload |

Maximale Paketgröße 128 Byte. Das Magic `0xA5` steht im `RowPacket`-Header und wird
beim Senden durch die Prüfsumme an Offset 0 überschrieben.

Prüfsumme ist ein CRC-8 mit Polynom `0x07`, Startwert `0x00`, ohne Reflektion —
allerdings in einer Variante, die erst schiebt und dann das MSB prüft:

```
crc = 0
für jedes Byte b:
    crc ^= b
    achtmal:
        crc = (crc << 1) & 0xFF
        wenn crc & 0x80:        # Test NACH dem Schieben
            crc ^= 0x07
```

Diese Reihenfolge weicht von der Lehrbuchvariante ab und muss genau so nachgebaut
werden, sonst verwirft die Firmware das Paket.

**Lüfter setzen** — Typ `STD_TYPE_USER_OVERRIDE`, ComType 30, OpType 2, Zieladresse 0.
Payload ist 8 Byte, **little-endian**:

| Offset | Größe | Feld |
|---|---|---|
| 0 | 1 | `commandType` |
| 1 | 1 | `fanSpeed` |
| 2 | 1 | `fanMode` |
| 3 | 1 | `zoneID` |
| 4 | 4 | `timeoutSec` |

`commandType`: `0` none, `1` global boost, `2` global pause, `3` zone boost,
`4` zone pause, `5` zone speed/mode, `6` zone vent profile, `7` cancel.

Beachte den Endianness-Bruch: der Zeitstempel im Header ist big-endian, die
Nutzdaten sind little-endian.

Weitere implementierte Kommandos (Auswahl aus 52 Request-Klassen): Boost, Pause,
Shutdown, Cancel, Zonenname und -schwelle, Lüftungsprofile inklusive Zeitslots,
Silent Hours, Filterwartungsintervall, Zeitsynchronisation, Geräte-RSSI,
WLAN-Konfiguration, Device-View-Abfragen sowie Firmware-Update.

Status lesen läuft über `DeviceViewHeader` + `DeviceViewPacketForRow`: das Kopfpaket
liefert die Zeilenzahl, danach wird je Gerät eine Zeile abgeholt. Feldtypen einer
Zeile unter anderem `ZONE_ID=1`, `DEVICE_STATUS=3`, `REPEATER_ENABLE=4`,
`FAN_POLARITY=32`.

## Weg B — BLE zum Connect-Regler (der Pfad für diese Hardware)

Der Regler exponiert **einen einzigen** Transport-Characteristic, über den Pakete
sowohl geschrieben als auch gelesen werden:

- Characteristic `e6ec2fd8-e888-4eb2-9681-e78ed6ea89e1`

Das ist kein Pax-Profil mit einem Characteristic je Funktion, sondern ein
paketorientierter Kanal. Die Fragmentierung ist selbstgebaut und läuft **poll-basiert**,
nicht über Notifications. Rahmen sind fest 20 Byte (klassische ATT-Payload bei MTU 23),
davon 3 Byte Rahmenkopf und 17 Byte Nutzlast:

| Offset | Größe | Feld |
|---|---|---|
| 0 | 1 | Fragmentindex (high nibble, 1-basiert) und Gesamtzahl (low nibble) |
| 1 | 1 | CRC-8 über die 17 Nutzlastbytes dieses Rahmens |
| 2 | 1 | Ack |
| 3 | 17 | Nutzlast |

Der CRC in Byte 1 verwendet dieselbe Routine wie die Paketprüfsumme oben. Das letzte
Fragment wird vor der CRC-Bildung mit Nullbytes auf 17 aufgefüllt.

**Senden** (`Utils.prepareProtocolData`): Fragmentzahl ist `ceil(packetSize / 17)`,
alle Rahmen werden am Stück geschrieben.

**Empfangen**: der Client liest denselben Characteristic wiederholt aus. Nutzlast ab
Offset 3, Ziel im Reassemblypuffer ist `(index - 1) * 17`. Der CRC in Byte 1 wird
beim Lesen ignoriert. Nach jedem Fragment schreibt der Client einen 20-Byte-Rahmen
mit `byte[2] = index` als Quittung und holt das nächste. Index `0` signalisiert
Fehler und führt zum Abbruch; Abbruch/Reset sendet `byte[2] = 0xFF`. Nach der
Reassemblierung muss `buffer[3]` dem erwarteten Pakettyp entsprechen, sonst verwirft
die App. Reassemblypuffer ist 256 Byte. Vor dem ersten Request wartet die App 100 ms,
Schreibvorgänge haben 10 s Timeout.

### Authentifizierung

Vor dem Nutzdatenverkehr läuft ein PIN-Handshake auf dem Connection-Service:

- Service `e6834e4b-7b3a-48e6-91e4-f1d005f564d3`
- PIN schreiben: `4cad343a-209a-40b7-b911-4d9b3df569b2`, 4 Byte Integer little-endian
- Bestätigung lesen: `d1ae6b70-ee12-4f6d-b166-d2063dcaffe1`

Die App liest die Hardware-Revision (`00002a27-…`) und verzweigt: bei `"02.00"` wird
zuerst die Geräte-UUID gelesen, sonst direkt der PIN-Pfad. Die PIN stammt je nach
Ablauf aus der Geräte-ID oder wird vom Gerät selbst gelesen — am realen Regler zu
klären, ob sie auf dem Typenschild steht oder in der App sichtbar ist.

### Praktische Bauform

BLE bindet einen Adapter an den Regler und ist reichweitenkritisch. Für Dauerbetrieb
ist ein **ESPHome-BLE-Proxy** in Reichweite des Reglers die realistische Lösung; der
HA-Host selbst steht meist zu weit weg. Da der Kanal poll-basiert ist und pro
Statusabfrage mehrere Round-Trips braucht, sollte die Integration einen
`DataUpdateCoordinator` mit moderatem Intervall verwenden und nicht pro Entity pollen.

Offen und am Gerät zu prüfen: ob der Regler parallele Verbindungen zulässt oder ob
die App die Verbindung exklusiv hält. Falls exklusiv, konkurrieren App und HA um den
Regler — dann ist die App nur noch als Rückfallebene nutzbar.

## Weg A — WLAN (nur mit WiFi-fähigem Regler, hier nicht vorhanden)

Dokumentiert für den Fall einer späteren Nachrüstung auf easy connect e16 WiFi.

**Discovery** — MDSDP über UDP-Broadcast, Port 47818. Suchpaket ist 8 Byte: ASCII
`MDSDP` + `0x03` (MSG_SEARCH) + 16-Bit-Transaktions-ID little-endian. Antwort ist ein
94-Byte-Announce mit IPv4-Adresse, 16-Byte-Geräte-UUID, Service-Type-UUID sowie
Namensfeldern (Device Name 64, Domain 32, Location 32 Byte). Nachrichtentypen:
`ANNOUNCE_V4=0`, `ANNOUNCE_V6=1`, `LEAVING=2`, `SEARCH=3`; Request-Flag `0x80`,
Not-implemented-Flag `0x40`, Typmaske `0x3F`. Sonde: `inventer-mdsdp-discover.py`
in diesem Verzeichnis.

**Transport** — TCP Port 47820 mit TLS-PSK, kein Zertifikat. Client bietet genau zwei
Cipher Suites an: `0x008C` (TLS_PSK_WITH_AES_128_CBC_SHA) und `0x008D`
(TLS_PSK_WITH_AES_256_CBC_SHA), dazu die Max-Fragment-Length-Extension (Wert 1).

Die **PSK-Identity ist fest `"12345"`**. Der PSK selbst ist ein String, den die App
**einmalig über BLE vom Regler ausliest** und danach lokal speichert:

- Service `e6834e4b-7b3a-48e6-91e4-f1d005f564d3`
- PSK: `638ff62c-3823-4e0f-8179-1695c46ee8ad`
- Geräte-UUID: `98faf8a5-1ee6-4b0c-911e-dc37bff5206f`

Darüber läuft dasselbe Zirconia-Paketformat wie bei BLE, nur ohne die 20-Byte-
Fragmentierung.

## Weg C — 0–10 V am sMove-Regler (andere Gerätegeneration)

Bei älteren Anlagen mit sMove-Regler ist Reverse Engineering überflüssig. Der sMove
hat einen 0–10-V-Steuereingang mit dokumentierten Spannungsfenstern (ca. 0 V Abluft
St. 3, 1 V Abluft St. 4, 2 V Abluft St. 2, 3 V Abluft St. 1, 4 V aus,
5–8 V Wärmerückgewinnung St. 1–4; Eingangsimpedanz ca. 6,4 kΩ). Ein Shelly-Dimmer
oder ein 0–10-V-Modul genügt.

## Nicht relevant hier: Pax-GATT-Profil für Einzelgeräte

Das SDK enthält zusätzlich das klassische Pax-Profil (Volution besitzt auch Pax) für
eigenständige Lüfter der Familien Calima/XFLP/Hyper — ein Characteristic je Funktion
statt eines Paketkanals. Für das Connect-System wird es nicht verwendet, für die
PIN-Charakteristiken und die Geräteinformationen aber schon. Festgehalten, falls
später ein Einzelgerät ohne Regler dazukommt.

Services: Config `c119e858-0531-4681-9674-5a11f0e53bb4`,
Connection `e6834e4b-7b3a-48e6-91e4-f1d005f564d3`,
Status `1a46a853-e5ed-4696-bac0-70e346884a26`.

| Funktion | UUID |
|---|---|
| Fan / Lüfterstufe | `7c4adc02-2f33-11e7-93ae-92361f002671` |
| Fan settings | `7c4adc07-2f33-11e7-93ae-92361f002671` |
| Humidity / System data | `7c4adc01-2f33-11e7-93ae-92361f002671` |
| Silent hour | `7c4adc03-2f33-11e7-93ae-92361f002671` |
| Silent hours enable / RTC | `7c4adc06-2f33-11e7-93ae-92361f002671` |
| Fan test | `7c4adc04-2f33-11e7-93ae-92361f002671` |
| User trigger | `7c4adc08-2f33-11e7-93ae-92361f002671` |
| Boost | `118c949c-28c8-4139-b0b3-36657fd055a9` |
| Mode | `90cabcd1-bcda-4167-85d8-16dcd8ab6a6b` |
| Basic ventilation | `faa49e09-a79c-4725-b197-bdc57c67dc32` |
| Automatic cycles | `f508408a-508b-41c6-aa57-61d1fd0d5c39` |
| Night mode | `b5836b55-57bd-433e-8480-46e4993c5ac0` |
| Sensor data | `528b80e8-c47a-4c0a-bdf1-916a7748f412` |
| Sensitivity | `e782e131-6ce1-4191-a8db-f4304d7610f1` |
| Level of fan speed | `1488a757-35bc-4ec8-9a6b-9ecf1502778e` |
| Clock | `6dec478e-ae0b-4186-9d82-13dda03c0682` |
| Time functions | `49c616de-02b1-4b67-b237-90f66793a6f2` |
| Status | `25a824ad-3021-4de9-9f2f-60cf8d17bded` |
| Reset | `ff5f7c4f-2606-4c69-b360-15aaea58ad5f` |

Für die Multi-Zonen-Variante (Momento) gilt Service
`75430500-d8c7-11e6-88f3-8fb4792b4153` mit Slot-basierten Characteristics
(`…0507` Slot-Auswahl, `…0508` Slot-Daten, `…0509` Slot-Name, `…0503` Heizstufe,
`…050e` Mode).

## Nächste Schritte

1. GATT-Scan des Reglers mit `inventer-ble-probe.py` in diesem Verzeichnis — bestätigt
   das Gerät, listet Services und prüft, ob `e6ec2fd8-…` vorhanden ist. Kein Schreiben,
   kein Risiko. Das Skript enthält zusätzlich Paketbau, Prüfsumme und Fragmentierung
   als nachnutzbare Bausteine; `--selftest` verifiziert sie ohne Hardware.
2. PIN klären (Typenschild, Handbuch oder App-Oberfläche) und den Handshake nachbauen.
3. Ein Device-View-Paket lesen — erster echter Protokoll-Round-Trip, immer noch
   lesend.
4. Erst danach ein `USER_OVERRIDE` schreiben, zunächst mit kurzem `timeoutSec`, damit
   der Regler von selbst zurückfällt.
5. Die Integration liegt unter `homeassistant/custom_components/inventer_connect`:
   `fan` mit Stufen 1-4 und Preset-Modes, dazu Sensoren und Binärsensoren über
   einen gemeinsamen `DataUpdateCoordinator`. Die Protokollschicht ist ohne
   Hardware testbar (`python3 -m pytest homeassistant/tests/test_protocol.py`).

## Zonen-Statusformat

Die Antwort auf `ZONE_VIEW_ROW` dekodiert die App in `ZoneInfoHelper.getZoneInfo()`.
Offsets zählen ab Beginn des reassemblierten Pakets, Werte sind little-endian:

| Offset | Typ | Feld |
|---|---|---|
| 17 | u8 | Lüfterstufe |
| 18 | u8 | playMode: 0 normal, 1 Pause, 2 Boost |
| 19 | i32 | Timer (Sekunden) |
| 23 | u8 | Flags: bit0 Timer aktiv, bit1 CO2-Sensor, bit2 externer Sensor, bit3 FCU, bit4 globaler Befehl |
| 24 | u8 | Lüftungsmodus |
| 25 | u8 | Lüftungsprofil |
| 30 | f32 | Komforttemperatur |
| 34 | f32 | Feuchte-Schwellwert |
| 38 | f32 | CO2-Schwellwert |
| 42 | f32 | VOC-Schwellwert |
| 46 | f32 | Außentemperatur |
| 50 | f32 | Außenfeuchte |
| 54 | f32 | Innentemperatur |
| 58 | f32 | Innenfeuchte |
| 62 | f32 | CO2 innen |
| 66 | f32 | VOC innen |
| 70 | f32 | System-Statusflag |
| 78 | i32 | Lüftungszeit |

Fehlende Sensoren liefert die Firmware als Unendlich; die App bildet das auf 0 ab.
Die Zeile ist damit mindestens 82 Byte lang und braucht fünf BLE-Rahmen.

Der Ablauf ist: `ZONE_VIEW_HEADER` (leere Payload, OpType 2) liefert die Zeilenzahl,
danach je Zone `ZONE_VIEW_ROW` mit dem Zonenindex als 1-Byte-Payload und OpType 1.

## Offene Punkte

- Zuordnung Zirconia ↔ konkretes Reglermodell am Gerät verifizieren.
- Ob der Regler parallele Verbindungen zulässt, ist praktisch zu testen.
- Die Bytes 0-16 und 26-29 sowie 74-77 der Zonenzeile sind noch nicht zugeordnet.
  Die Diagnose der Integration gibt die Rohzeile als Hex aus — daraus lässt sich
  der Rest bestimmen.
- Lüftungsmodus-Werte (Offset 24) sind als Index bekannt, ihre Bedeutung nicht.
