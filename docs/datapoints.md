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
