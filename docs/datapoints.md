# Popur S7 App-2 datapoint inventory

This is the complete 40-datapoint set returned by the authorized firmware-4 S7's current mobile
device record. “LAN” means the point was also observed in ordinary authenticated Tuya 3.5 status
on both the local Mac and the in-home Pi. A cloud-only point is still part of the device schema and
app cache; this firmware simply did not return it to LAN status or explicit UPDATEDPS reads.

| DP | Current App-2 meaning | Shape | LAN | `pypopur` |
| ---: | --- | --- | :---: | --- |
| 1 | cleaning run/pause control | bool | yes | read + action |
| 7 | daily clean count | integer | yes | decoded |
| 8 | clean duration | integer | yes | decoded |
| 10 | do-not-disturb schedules | RAW | no | raw access |
| 12 | automatic clean count | integer | yes | decoded |
| 14 | scheduled cleaning entries | RAW | no | raw access |
| 15 | scheduled clean count | integer | no | decoded |
| 19 | manual clean count | integer | no | decoded |
| 20 | additional schedule/settings payload | RAW | no | raw access; exact current layout unresolved |
| 22 | recent activity | enum/scalar | yes | decoded |
| 31 | dustbin door control | bool | no | action API |
| 101 | run mode: bin/running/machine/pet/countdown | RAW, 5 bytes | no | decoded + encoded |
| 102 | system settings | RAW, 29 bytes | no | decoded + safe read-modify-write model |
| 103 | power timers and hibernate | RAW, 10 bytes | no | decoded + encoded |
| 104 | dustbin settings | RAW, 3 bytes | no | decoded + safe read-modify-write model |
| 105 | panel key settings | RAW, 7 bytes | no | decoded + safe read-modify-write model |
| 106 | self-check progress | RAW, 5 bytes | no | decoded + encoded |
| 107 | dustbin zero / spin-sensor calibration | enum command | no | action API |
| 108 | sifter control | enum command | no | action API |
| 109 | power/reboot control and current machine state | enum | yes | decoded + action API |
| 110 | self-check start/stop | bool | yes | action API |
| 111 | scale recalibration | bool command | no | action API |
| 112 | notification master | bool | yes | decoded + encoded |
| 113 | pet detected notification | bool | yes | decoded + encoded |
| 114 | pet finished notification | bool | yes | decoded + encoded |
| 115 | pet left notification | bool | yes | decoded + encoded |
| 116 | total use time | integer | yes | decoded |
| 117 | cleaning started notification | bool | yes | decoded + encoded |
| 118 | cleaning paused notification | bool | yes | decoded + encoded |
| 119 | cleaning resumed notification | bool | yes | decoded + encoded |
| 120 | automatic cleaning notification | bool | yes | decoded + encoded |
| 121 | scheduled cleaning notification | bool | yes | decoded + encoded |
| 122 | manual cleaning notification | bool | yes | decoded + encoded |
| 123 | bin-full notification | bool | yes | decoded + encoded |
| 124 | self-check-complete notification | bool | yes | decoded + encoded |
| 125 | self-check fault bitmask | integer/hex | yes | decoded to fault list |
| 126 | cat presence | enum/scalar | no | retained raw; also decoded in DP101 when available |
| 146 | clean count after bin full/zero | integer | yes | decoded |
| 150 | fault-free use time | integer | no | decoded |
| 152 | lifetime clean count | integer | yes | decoded |

The generic `UnifiedDeviceControlHelper` contains methods for several older product generations as
well. Those methods are not evidence that this S7 supports an extra datapoint. This inventory uses
the live product record to filter that generic surface and the current S7 screen call sites to
resolve collisions such as DP110: the current self-check UI writes DP110, while DP3 survives only
as a legacy constant.

No action or settings write was sent during live verification. Action encodings above come from
the official App-2 APK and synthetic transport tests. Packed settings writes preserve unknown and
reserved bytes, and targeted mutations refuse to proceed when the current packed payload is not
available.

## Activity and fault events

`pypopur.extract_activity_events(dps, previous_raw=None)` turns one received DP report into a
list of `ActivityEvent(event_type, dp, raw_value, attributes)`. It is a pure function: the caller
timestamps events at reception and decides which frames to feed it (live MQTT pushes, not polled
or refreshed snapshots, otherwise the current state would be replayed).

- **DP22 is the only activity trigger.** A live MQTT capture (firmware pv 2.3) showed DP22 arrives
  as a string (`cat_exist`, `cat_done_business`, `cleaning_started`, `manual_clean_completed`, …),
  once per real event, one DP per frame, with no `dpsTime`. Every DP22 yields an event, even when
  it repeats the previous value. `idle` and unknown values yield nothing. Event types are listed
  in `ACTIVITY_EVENT_TYPES` (the non-idle `RecentActivity` names in lower case).
- **DP101 never yields events.** The firmware re-sends it unchanged and once per countdown minute.
- **DP125** yields one `fault_detected` / `fault_cleared` per bit that changed against
  `previous_raw[125]`, with `attributes = {"fault", "url", "mask"}` (`FAULT_EVENT_TYPES`). Without a
  previous mask nothing is emitted, to avoid spurious events at startup. DP125 has not been
  observed live yet.
- Cloud protocol-56 alerts (push-notification rules) duplicate DP22 and are out of scope.
