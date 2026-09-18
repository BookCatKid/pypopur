# Popur Home Assistant integration

Local custom component for the Popur S7, built on the `pypopur`
library (a byte-faithful port of the Popur Android App 2.0.0 SDK).

## Install

`pypopur` is not on PyPI, so install it into Home Assistant's Python
environment first:

```bash
# HA OS / container / venv — wherever `homeassistant` lives:
pip install -e /path/to/pypopur
```

Then link the component into your HA config:

```bash
ln -s /path/to/pypopur/custom_components/popur \
      /path/to/homeassistant_config/custom_components/popur
```

Restart Home Assistant, then **Settings → Devices & Services → Add
Integration → Popur** and sign in with your Popur app credentials.

## What you get

**Device** (per litter box, cloud-polled + real-time MQTT push)

- Sensors: machine/running status, waste-drawer level, cat presence,
  recent activity, cat weight, clean countdown, daily/total/after-full
  cycle counts, per-mode cycle counts, use/clean/toilet durations,
  fault-free time, self-check progress (fault labels in attributes)
- Binary sensors: bin full, cat present, cleaning, fault, powered
- Switches: power, status light, buzzer, anti-interference, auto clean,
  sentinel/caring mode, track pet data, auto power cycle, lower drum
  speed, litter reshuffle, auto self-check, notifications, all five
  drawer toggles (bin-full detection, allow overfill, keep upright,
  block on full, dump override), child lock
- Buttons: clean now / pause / resume, self-check, sifter open/close,
  scoop start/pause, drawer open/close, reset bin level, recalibrate
  spin sensor, recalibrate scale, reboot
- Selects: drawer calibration level, device color, reshuffle oscillation
- Numbers: clean delay (1–60 min), radar sensitivity (1–10), radar
  range (1–5), smooth spread count (2–7), drawer cycle count (1–10)

**Per pet** (linked to the litter box device)

- Last measured weight, last visit duration, last visit timestamp —
  decoded from the `toilet_usage_data` records the S7 reports
  (per-visit weight + seconds, same as the app's pet stats).

## Notes

- Writes go through the app's own HTTP DP-publish path; the cloud
  shadow is also the read source, so state matches what the app shows.
- Real-time updates ride the app's MQTT channel when the broker is
  reachable; polling (default 60 s, min 15 s) always runs.
- All writes are real device commands — same endpoints the app calls.
