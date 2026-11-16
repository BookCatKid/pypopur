# pypopur

**Experimental** — a reverse-engineered Python client for the Popur S7 smart litter box, built from static analysis of the official Android app (v2.0.0 / ThingClips SDK). Tested against a single real device; expect rough edges.

[![PyPI](https://img.shields.io/pypi/v/pypopur)](https://pypi.org/project/pypopur/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://github.com/BookCatKid/pypopur/actions/workflows/ci.yml/badge.svg)](https://github.com/BookCatKid/pypopur/actions/workflows/ci.yml)

## Features

- **LAN control** — Tuya protocol 3.5 session-key negotiation, DP read/write over TCP:6668, auto-protocol probing (3.1–3.5), heartbeat keepalive, stale-session recovery
- **Cloud APIs** — full ThingClips/Popur app surface: auth, homes, devices, DP shadow, pets, pet records, firmware, timers, device management
- **MQTT events** — real-time DP deltas and alert events over TLS to the app's broker, with reconnect/resubscribe handling
- **Hybrid transport** — LAN-first with automatic cloud fallback; slow reconciliation tier for settings DPs and pet data the LAN omits
- **Discovery** — passive UDP announcements plus active host location via ARP MAC match and port-6668 subnet scan
- **DP codecs** — all firmware-4 packed payloads decoded (settings, calibration, radar config, cat weight, visit records)
- **Pet tracking** — household pet profiles, per-visit weight/duration records decoded from the app's own format
- **Home Assistant integration** — full entity coverage (sensors, switches, buttons, numbers, selects) in `custom_components/popur/`

## Install

```bash
pip install pypopur
```

Requires Python 3.11+.

## Quick start — local control

```python
import asyncio
from pypopur import LocalTuyaTransport, PopurClient

async def main():
    transport = LocalTuyaTransport(
        device_id="your-device-id",
        host="192.168.1.x",
        local_key="your-local-key",
    )
    client = PopurClient(transport)

    async with client:
        snapshot = await client.refresh()
        print(snapshot.machine_status, snapshot.cat_present, snapshot.bin_full)
        await client.start_cleaning()

asyncio.run(main())
```

## Quick start — cloud account

```python
import asyncio
from pypopur.mobile import MobileAppProfile, PopurAccount, ThingMobileApi

async def main():
    api = ThingMobileApi(
        MobileAppProfile.bundled_popur_app2(),
        install_id="a-stable-id-for-this-install",
    )
    account = PopurAccount(api)
    await account.login("you@example.com", "your-password")

    home_id = (await account.homes())[0]["gid"]
    devices = await account.home_devices(home_id)

    for dev in devices:
        print(dev.name, dev.device_id, dev.local_key)

asyncio.run(main())
```

## Quick start — pets

```python
pets = await account.pets(home_id)
for pet in pets:
    print(pet.name, pet.pet_type, pet.weight)

page = await account.pet_records(home_id, page_size=50)
for record in page.records:
    usage = record.toilet_usage()
    if usage:
        print(record.pet_id, usage.weight_grams, "g", usage.duration_seconds, "s")
```

## Quick start — MQTT events

```python
events = account.connect_events(
    devices={dev.device_id: dev.local_key},
    on_event=lambda e: print(e.dev_id, e.dps),
    on_connect=lambda: print("connected"),
)
await events.connect()
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  PopurClient                     │
│         typed controls + DeviceSnapshot          │
├─────────────────────────────────────────────────┤
│              FallbackTransport                   │
│   LAN primary (3.5) ──fail──► Cloud fallback    │
├──────────┬──────────────────┬───────────────────┤
│ LAN TCP  │  MQTT TLS        │  Cloud HTTPS      │
│ :6668    │  smart/mb/in/    │  a1.tuyaus.com    │
│ DP r/w   │  DP deltas       │  shadow, pets,    │
│ ~23 DPs  │  alerts          │  mgmt APIs        │
└──────────┴──────────────────┴───────────────────┘
```

- **LAN** — fast path for reads/writes; ~23 DPs in status responses
- **MQTT** — real-time push (protocol-4 deltas, protocol-56 alerts); deltas only, no snapshots
- **Cloud** — settings DPs LAN omits (102 etc.), pet profiles/records, firmware, timers, device management

## Home Assistant

The integration lives in `custom_components/popur/` — install via HACS custom repository or copy the directory to your HA `custom_components/`. See [`custom_components/popur/README.md`](custom_components/popur/README.md) for details.

## Status

- **Tested against**: one Popur S7 (Wi-Fi 3.0.30 / MCU 4.3.0), firmware-4 protocol family
- **LAN protocol**: verified live — handshake, DP read/write, heartbeat, reconnect
- **Cloud APIs**: signature-exact to the app; read paths verified live, write paths untested
- **MQTT**: verified live — connect, subscribe, decode protocol-4/56 frames, reconnect
- **Test suite**: 769 tests, all passing

## Limitations

- Only tested against one device and one firmware version — other S7s may differ
- App-layer write APIs (pets, device management) are signature-verified but never executed live
- The standalone LAN transport doesn't fetch the thing model — no schema validation on writes
- MQTT is event-driven (deltas only) — it can't replace polling for state seeding or reconciliation
- Settings DPs and pet data require the cloud — they don't exist on the LAN channel

## Development

```bash
python -m pytest tests/          # 769 tests
ruff check src tests             # lint
```

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This is an unofficial, reverse-engineered client. It is not affiliated with or endorsed by Popur. Use at your own risk — the author is not responsible for bricked devices, angry cats, or unexpected litter box behavior.
