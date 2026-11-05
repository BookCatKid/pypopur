"""Capture everything the Popur cloud MQTT channel pushes, as JSONL.

    uv run python examples/capture_events.py \
        --email-file /path/to/email --password-file /path/to/password \
        --duration 1800 --out ~/.cache/pypopur-capture/

Credentials are read from files (``--email-file``/``--password-file`` or
the ``POPUR_EMAIL_FILE``/``POPUR_PASSWORD_FILE`` env vars) and never
written anywhere. The login uses its own stable install id, stored in
``~/.cache/pypopur-capture/install_id`` (distinct from Home Assistant's).

Every line of the output file is one JSON record with a ``kind``:

- ``raw``: every inbound PUBLISH as handed to ``MqttServerManager.parse_message``
  (topic, size, text or base64 payload) plus whether it reached a listener
  callback (``dropped_silently`` = no ``on_event``/``on_error`` fired);
- ``event``: each decoded :class:`DeviceEvent` (protocol, full ``data``,
  ``dps``, ``dps_time`` + readable DP22/DP101/DP125 decodes);
- ``error``: ``on_error`` callbacks (decode failures, dedup drops, connect errors);
- ``status``: login/connect/subscribe/heartbeat/close milestones.

Secrets are masked: password/localKey/sid/ecode are never written, devId
and uid keep their last 4 characters only. JSON payloads are parsed so
secret-named keys are redacted too. Output directories are created 0700
and capture files 0600 (owner only).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from pypopur.dps import decode_dp22, decode_dp101, decode_dp125, decode_dp125_value
from pypopur.events import DeviceEvent
from pypopur.mobile import MobileAppProfile, PopurAccount, ThingMobileApi

CACHE_DIR = Path.home() / ".cache" / "pypopur-capture"
SECRET_KEYS = {"localkey", "sid", "token", "ecode", "seckey", "password", "passwd", "secret"}


def read_secret_file(path: str | None, env: str) -> str:
    path = path or os.environ.get(env)
    if not path:
        raise SystemExit(f"missing credential file (argument or ${env})")
    return Path(path).expanduser().read_text().strip()


def private_dir(path: Path) -> None:
    """Create ``path`` (owner-only if we create it)."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def stable_install_id() -> str:
    private_dir(CACHE_DIR)
    path = CACHE_DIR / "install_id"
    if path.exists():
        return path.read_text().strip()
    value = uuid.uuid4().hex
    path.write_text(value)
    return value


class Masker:
    """Replace every known secret substring in strings, recursively."""

    def __init__(self) -> None:
        self._redact: list[str] = []  # removed entirely
        self._shorten: list[str] = []  # keep last 4 chars

    def redact(self, value: str | None) -> None:
        if value and len(value) >= 4:
            self._redact.append(value)

    def shorten(self, value: str | None) -> None:
        if value and len(value) >= 6:
            self._shorten.append(value)

    def text(self, value: str) -> str:
        for secret in sorted(self._redact, key=len, reverse=True):
            value = value.replace(secret, "<redacted>")
        for ident in sorted(self._shorten, key=len, reverse=True):
            value = value.replace(ident, "…" + ident[-4:])
        return value

    def __call__(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                key = self.text(str(k))
                if str(k).lower() in SECRET_KEYS and v not in (None, ""):
                    out[key] = "<redacted>"
                else:
                    out[key] = self(v)
            return out
        if isinstance(obj, (list, tuple)):
            return [self(v) for v in obj]
        if isinstance(obj, (bytes, bytearray)):
            return self(_payload_view(bytes(obj)))
        return obj


def _payload_view(payload: bytes | None) -> dict[str, Any]:
    if payload is None:
        return {"payload": None}
    try:
        text = payload.decode("utf-8")
        if text.isprintable() or text.lstrip().startswith("{"):
            try:
                # Parsed, so Masker redacts secret-named keys as well.
                return {"payload_json": json.loads(text)}
            except ValueError:
                return {"payload_text": text}
    except UnicodeDecodeError:
        pass
    return {
        "payload_b64": base64.b64encode(payload).decode(),
        "payload_prefix": payload[:3].decode("latin-1"),
    }


def _decode_dps(dps: dict[int, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if 22 in dps:
        act = decode_dp22(dps[22])
        out["dp22"] = {
            "raw": dps[22],
            "raw_type": type(dps[22]).__name__,
            "activity": act.name if act is not None else None,
        }
    if 101 in dps:
        try:
            rm = decode_dp101(dps[101])
            out["dp101"] = None if rm is None else {
                "bin": rm.bin_status.name,
                "running": rm.running_status.name,
                "machine": rm.machine_status.name,
                "cat": rm.cat_presence.name,
                "countdown_min": rm.countdown_minutes,
            }
        except Exception as err:  # noqa: BLE001
            out["dp101"] = {"decode_error": repr(err)}
    if 125 in dps:
        out["dp125"] = {
            "raw": dps[125],
            "value": decode_dp125_value(dps[125]),
            "faults": [f.label for f in decode_dp125(dps[125])],
        }
    return out


class Recorder:
    def __init__(self, path: Path, masker: Masker) -> None:
        self.path = path
        self.mask = masker
        self._lock = threading.Lock()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)  # also tighten a pre-existing file
        self._fh = os.fdopen(fd, "a", encoding="utf-8")
        self.counts: dict[str, int] = {}
        self._local = threading.local()

    def write(self, kind: str, **fields: Any) -> None:
        record = {"ts": datetime.now().astimezone().isoformat(timespec="milliseconds"), "kind": kind}
        record.update(fields)
        line = json.dumps(self.mask(record), ensure_ascii=False, default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            self.counts[kind] = self.counts.get(kind, 0) + 1
        # also mirror to stdout (masked) so progress is visible
        print(line[:400], flush=True)

    # Per-message callback counter: set by the parse_message wrapper so the
    # raw record can say whether the frame reached on_event/on_error.
    def callback_fired(self) -> None:
        self._local.fired = getattr(self._local, "fired", 0) + 1

    def reset_fired(self) -> None:
        self._local.fired = 0

    def fired(self) -> int:
        return getattr(self._local, "fired", 0)

    def close(self) -> None:
        self._fh.close()


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--email-file")
    ap.add_argument("--password-file")
    ap.add_argument("--duration", type=float, default=1800, help="seconds (default 1800)")
    ap.add_argument("--out", default=str(CACHE_DIR), help="output dir or .jsonl path")
    ap.add_argument("--country-code", default="1")
    args = ap.parse_args()

    email = read_secret_file(args.email_file, "POPUR_EMAIL_FILE")
    password = read_secret_file(args.password_file, "POPUR_PASSWORD_FILE")

    out = Path(args.out).expanduser()
    if out.suffix != ".jsonl":
        private_dir(out)
        out = out / f"capture-{datetime.now():%Y%m%d-%H%M%S}.jsonl"
    else:
        private_dir(out.parent)

    masker = Masker()
    masker.redact(password)
    masker.redact(email)
    rec = Recorder(out, masker)
    print(f"writing to {out}", flush=True)

    install_id = stable_install_id()
    api = ThingMobileApi(MobileAppProfile.bundled_popur_app2(), install_id=install_id)
    account = PopurAccount(api)
    session = await account.login(email, password, country_code=args.country_code)
    masker.redact(session.sid)
    masker.redact(session.ecode)
    masker.shorten(session.uid)
    rec.write("status", step="login", install_id_tail=install_id[-4:],
              partner_identity=session.partner_identity,
              mqtt_host=(session.domain or {}).get("mobileMqttsUrl"))

    homes = await account.homes()
    home_id = homes[0]["gid"]
    masker.shorten(str(home_id))
    devices = await account.home_devices(home_id)
    for dev in devices:
        masker.shorten(dev.device_id)
        masker.redact(dev.local_key)
        masker.shorten(dev.mac)
    rec.write("status", step="devices", home_id=str(home_id),
              devices=[{"dev_id": d.device_id, "name": d.name, "product_id": d.product_id,
                        "has_local_key": bool(d.local_key)} for d in devices])

    local_keys = {d.device_id: d.local_key for d in devices if d.local_key}

    def on_event(event: DeviceEvent) -> None:
        rec.callback_fired()
        dps = dict(event.dps)
        rec.write(
            "event",
            topic=event.topic,
            dev_id=event.dev_id,
            protocol=event.protocol,
            data=dict(event.data),
            dps={str(k): v for k, v in dps.items()},
            dps_time={str(k): v for k, v in event.dps_time.items()},
            decoded=_decode_dps(dps),
        )

    def on_error(topic: str, code: str, msg: str) -> None:
        rec.callback_fired()
        rec.write("error", topic=topic, code=code, msg=msg)

    connects = 0

    def on_connect() -> None:
        nonlocal connects
        connects += 1
        rec.write("status", step="mqtt_connected", n=connects)

    events = account.connect_events(
        devices=local_keys, on_event=on_event, on_error=on_error, on_connect=on_connect
    )

    # Non-invasive raw hook: shadow the manager's parse_message on this
    # instance — the wire client calls ``self.manager.parse_message`` for
    # every inbound PUBLISH, before any decoding/drop decision.
    manager = events.manager
    original_parse = manager.parse_message

    def parse_and_log(topic: str, payload: bytes | None) -> None:
        rec.reset_fired()
        received = datetime.now().astimezone().isoformat(timespec="milliseconds")
        try:
            original_parse(topic, payload)
        finally:
            rec.write(
                "raw",
                received=received,
                topic=topic,
                size=None if payload is None else len(payload),
                dropped_silently=rec.fired() == 0,
                **_payload_view(payload),
            )

    manager.parse_message = parse_and_log  # type: ignore[method-assign]

    await events.connect()
    rec.write("status", step="subscribed", topics=list(events._subscriptions))
    print("=== READY: connection up and subscriptions sent ===", flush=True)

    deadline = time.monotonic() + args.duration
    try:
        while time.monotonic() < deadline:
            await asyncio.sleep(min(60, max(0.0, deadline - time.monotonic())))
            rec.write("status", step="heartbeat", connected=events.connected,
                      counts=dict(rec.counts))
    finally:
        await events.close()
        rec.write("status", step="closed", counts=dict(rec.counts))
        rec.close()


if __name__ == "__main__":
    asyncio.run(main())
