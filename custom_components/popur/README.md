# Popur — Home Assistant Integration

**Experimental** — controls the Popur S7 smart litter box via LAN (preferred) and cloud (fallback/settings/pets). Built on [`pypopur`](https://github.com/BookCatKid/pypopur).

## Features

- **Local-first** — LAN control over TCP:6668 (Tuya protocol 3.5); routine polling never touches Tuya's servers
- **Real-time events** — MQTT push for instant state updates (cat left, bin full, cleaning started)
- **Pet tracking** — per-pet weight, visit duration, and last-visit sensors
- **Full entity coverage** — 18 sensors, 5 binary sensors, 19 switches, 14 buttons, 3 selects, 5 numbers per device
- **Cloud fallback** — automatic fallback to cloud APIs when LAN is unreachable; settings DPs and pet data always via cloud
- **Auto-discovery** — finds the S7 on the LAN via ARP MAC match + port scan; optional explicit host override

## Install via HACS

1. Add `https://github.com/BookCatKid/pypopur` as a **custom repository** in HACS (type: Integration)
2. Install "Popur"
3. Restart Home Assistant
4. **Settings → Devices & Services → Add Integration → Popur**

## Install manually

```bash
pip install pypopur
cp -r custom_components/popur /config/custom_components/
```

Restart Home Assistant, then add the integration.

## Configuration

| Field | Required | Description |
|-------|----------|-------------|
| **Email** | Yes | Popur app account email |
| **Password** | Yes | Popur app account password |
| **Install ID** | No | App-install identity — leave blank to auto-generate (recommended) |
| **LAN Host** | No | Explicit device IP — leave blank to auto-discover |
| **Poll Interval** | No | LAN poll interval in seconds (default: 60, min: 15) |

## Entities

### Sensors (18 per device)

Machine status, running status, waste drawer level, cat presence, recent activity, cat weight, countdown, daily/total/after-full counts, manual/scheduled/auto counts, use/clean/toilet durations, fault-free time, self-check progress.

### Binary sensors (5)

Bin full, cat present, cleaning, fault, powered.

### Switches (19)

Power, status light, buzzer, anti-interference, auto clean, sentinel, caring, track pet data, auto power cycle, lower speed, reshuffle, auto self-check, notifications, 5 drawer toggles, child lock.

### Buttons (14)

Clean, pause, resume, self-check, sifter open/close, scoop start/pause, drawer open/close, zero bin, recalibrate spin/scale, reboot.

### Selects (3)

Calibration level, device color, reshuffle oscillation.

### Numbers (5)

Clean delay (1–60), radar sensitivity (1–10), radar range (1–5), smooth spread (2–7), cycle count (1–10).

### Per-pet sensors (3 per pet)

Last measured weight, last visit duration, last visit timestamp.

### Diagnostics

Connection sensor — shows `lan` (local control active) or `cloud` (fallback).

## How it works

```
LAN (every poll interval)     ← device state, writes, reads
MQTT (real-time)              ← DP deltas, alerts — instant updates
Cloud (every ~10 min)         ← settings DPs, pets, records
Cloud (on LAN failure)        ← fallback for all operations
```

- **LAN** is the fast path — reads/writes go over the local network when available
- **MQTT** provides real-time push — entities update instantly on state changes, not on poll interval
- **Cloud** fills the gaps — settings DPs the LAN omits, pet profiles/records, firmware info
- **Fallback** — if LAN drops, the transport automatically falls back to cloud and retries LAN periodically

## Pet records

When a cat leaves the litter box (`cat_left` event via MQTT), the integration fetches the latest record ~45 seconds later — near-real-time weight and duration without hammering the cloud API.

## Limitations

- Only tested against one Popur S7 (firmware 4.x) — other devices may differ
- All write operations send real device commands — use with care
- The S7 allows a single LAN session at a time — if the app or another client is connected, the integration falls back to cloud until the session frees up

## License

MIT — same as [pypopur](https://github.com/BookCatKid/pypopur/blob/main/LICENSE).
