# pypopur

`pypopur` is an async, local-first Python client and protocol model for the Popur S7 running
firmware 4.x with the app-v2 protocol family. It is built from static analysis of the official
Popur S7 Android v2.0.0 APK.

The useful split is simple:

- all dedicated firmware-4 packed DP models found in the app are decoded and encoded;
- local control uses a device ID, LAN address, and per-device Tuya `localKey`;
- passive LAN discovery identifies the current S7 product family before authentication;
- the App-2 Thing mobile account bootstrap is implemented as a separate async layer: two-stage
  email/password login, session setup, home/device queries, and `localKey` retrieval;
- the version-bound OEM app identity/security material is bundled from the distributed App-2 APK,
  and the APK extractor can independently reconstruct and check it;
- after bootstrap, normal operation can stay entirely local;
- a cloud transport interface exists so a supported account backend can be added without changing
  the client or DP model.

## Local client

For local development, install the package from this source tree; TinyTuya is the LAN transport
dependency. `pypopur` is not published to PyPI as part of this local-only work:

```fish
python -m pip install .
```

Then provide credentials for a device you own:

```python
from pypopur import PopurClient

client = PopurClient.local(
    host="192.0.2.40",
    device_id="your-device-id",
    local_key="your-device-local-key",
)

async with client:
    snapshot = await client.refresh()
    print(snapshot.run_mode)
    await client.start_cleaning()
```

`protocol_version=None` is the default. The transport makes read-only status probes using 3.5,
3.4, and then 3.3. The bundled Thing SDK contains 3.3, 3.4, 3.5, and a distinct 3.5.1 branch;
TinyTuya's ordinary version API covers the first three. A passive LAN discovery of one real
firmware-4 S7 observed protocol 3.5, while the fallback probes keep the client usable without
assuming every firmware-4 unit negotiates the same version. Set an explicit version when known.

Local-key bootstrap is separate from the LAN transport. `discover_s7()` passively identifies an
S7, and `PopurAccount.bootstrap_local_config()` resolves that discovered device through an
authenticated Thing mobile session. The returned `LocalDeviceConfig` can then be used for LAN
operation. Keys and account-session secrets are excluded from object `repr()` output.

For the verified Popur App 2.0.0 APK, `MobileAppProfile.from_popur_app2_apk()` performs the native
bootstrap locally. It reads the OEM app constants from the APK's DEX `BuildConfig`, extracts the
APK v2/v3 signing certificate fingerprint, decodes the current-generation `assets/t_s.bmp`
security component, derives `chKey`, and recreates the native request/encryption master.
`MobileAppProfile.bundled_popur_app2()` provides the same version-bound app-shipped identity without
requiring the APK at setup time. `MobileAppProfile.for_popur_app2()` remains available for callers
that already have those inputs.

A complete discovery-to-LAN bootstrap can therefore be written without manually copying a device
ID, `localKey`, or OEM app values:

```python
from pypopur import bootstrap_discovered_s7_popur_app2, discover_s7

devices = await discover_s7()
config = await bootstrap_discovered_s7_popur_app2(
    devices[0],
    email="you@example.com",
    password="your-popur-password",
)

# Store `config` securely; normal operation can now use PopurClient.local(...)
# without keeping the Popur password or mobile session.
```

The current implementation mirrors the App-2 token/RSA password flow, native ATOP HMAC-SHA256
signing, per-request HMAC key derivation, AES-GCM `et=3` envelope, SDK HTTP headers, encrypted
response-signature verification, post-login regional API-host handoff, home/device enumeration,
and `localKey` retrieval recovered from the APK. The request flow is covered by an offline
synthetic server, and the APK-material derivation path is additionally smoke-tested locally against
the inspected Popur APK. The complete read-only account path was also validated against the live
US service with App 2.0.0 in September 2026: password login, home and device enumeration, device
detail, and `localKey` retrieval all succeeded. A real account login is deliberately not part of
the automated test suite.

The profile can also carry the ordinary Thing request metadata (`channel`, `deviceCoreVersion`,
Android/system model, timezone, SDK level, brand, `bizData`, and other common parameters) instead
of fabricating phone-specific values. `derive_android_device_id()` reproduces the SDK's persisted
`PhoneUtil.getRemoteDeviceID()` calculation when the Android random-ID inputs are available.
Credential-equivalent app identity/native security material is redacted from `repr()` output. The
bundled App-2 profile is explicitly version-bound to the audited Popur 2.0.0 APK; callers can use
the APK-derived or explicit-profile constructors instead when they do not want that material
packaged with the library.

## Passive discovery

`discover_s7()` listens for Tuya LAN advertisements through TinyTuya and returns only devices whose
product IDs match the S7 identifiers recovered from Popur App 2. Discovery is read-only and does
not require a local key. TinyTuya's current `productKey` broadcast field and the older
`productId`/`product_id` spellings are all recognized:

```python
from pypopur import discover_s7

devices = await discover_s7()
for device in devices:
    print(device.host, device.device_id, device.protocol_version)
```

The discovery result feeds the account-bootstrap flow so users do not need to type an IP address
or device ID manually.

## API shape

`PopurClient` has public idempotent `connect()` and `close()` methods as well as an async context
manager. `refresh()` returns an immutable `DeviceSnapshot`, with raw DPS retained alongside
decoded v4 objects. Direct `read_dps()` / `write_dps()` remain available for fields that have not
been given a high-level method.

`PopurAccount.device_dps()` and `device_snapshot()` read the complete mobile device record. On the
validated S7 this contains 40 current datapoints, including packed settings that its ordinary LAN
status reply omits. The LAN path reports 23 active datapoints on the same firmware.

Packed settings use typed models and atomic read-modify-write helpers. For common DP102 controls,
the targeted setters always read a fresh payload while holding the client's mutation lock:

```python
await client.set_status_light(True)
await client.set_buzzer(False)
await client.set_clean_delay(10)
await client.set_radar_sensitivity(6)
await client.set_radar_range(3)
```

The APK-backed action API also covers current S7 power/reboot, self-check start/stop, dustbin
open/close and zeroing, sifter open/close/scoop/pause, scale recalibration, and spin-sensor
recalibration. These encodings have static and synthetic-test coverage; no live write was sent
during the read-only device audit.

For DP102, the original 29-byte payload is retained in `SystemSettings.raw`. Encoding changes only
known fields whose model value differs from that raw payload's decoded baseline, preserving
reserved bytes, unknown weight-function bits, and unusual firmware values that the app displays
through fallbacks. This matches the app's read-modify-write approach and avoids unrelated cleanup
of device state.

See [`docs/protocol.md`](docs/protocol.md) for the byte layouts, standalone notification DPs,
legacy-ID collisions, and local/cloud capability boundaries.

## Development

The LAN transport depends on TinyTuya. The test suite injects a fake local device and uses
`unittest`, so the protocol and lifecycle layers can be verified without network access or a live
S7:

```fish
env PYTHONPATH=src python -m unittest discover -s tests -v
ruff check src tests
```

A live read-only run against a real firmware-4 S7 has validated passive discovery, account/device
matching, local-key retrieval, the Tuya 3.5 handshake, and authenticated local status polling.
Command behavior and the LAN availability of every DP still need live-device validation. The
tests validate the static APK model, encoder behavior, transport lifecycle, error classification,
concurrency, and synthetic TinyTuya responses.
