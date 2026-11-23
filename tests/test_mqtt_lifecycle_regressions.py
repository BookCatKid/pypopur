"""Regression tests for MQTT lifecycle races across operating systems.

Use actual MQTT wire clients and local TCP brokers. Thread coordination
reproduces interleavings instead of relying on network outages or devices.
"""

from __future__ import annotations

import socket
import threading

from test_mqtt_client import FakeBroker, _client, _wait_for


def test_close_reliably_wakes_socket_reader() -> None:
    """Closing a session must terminate its blocked reader promptly.

    A single attempt often passes on macOS even when shutdown occasionally
    leaves the reader stuck in recv() until its 90-second read timeout.
    """
    for attempt in range(24):
        broker = FakeBroker()
        _, client = _client(broker, tag=f"t-close-stress-{attempt}")

        try:
            client.connect()
            reader = client._reader
            assert reader is not None and reader.is_alive()

            client.close()
            reader.join(timeout=0.5)

            assert not reader.is_alive(), (
                f"MQTT reader survived close() on attempt {attempt}"
            )
        finally:
            client.close()
            broker.stop()


def test_superseded_connect_does_not_emit_success_callback() -> None:
    """A delayed success notification cannot belong to a later session."""
    broker = FakeBroker()
    _, client = _client(broker, tag="t-stale-connect-success")
    first_notification = threading.Event()
    release_first_notification = threading.Event()
    notifications: list[bool] = []
    worker_errors: list[BaseException] = []

    class Status:
        def on_connect_success(self) -> None:
            notifications.append(client.connected)

        def on_connect_error(self, code: str, error: str) -> None:
            pass

    client.register_mqtt_callback(Status())
    notify = client._notify_connect_success
    calls = 0

    def delayed_notify() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            first_notification.set()
            if not release_first_notification.wait(timeout=5):
                raise TimeoutError("connection callback was not released")
        notify()

    client._notify_connect_success = delayed_notify

    def connect_first() -> None:
        try:
            client.connect()
        except Exception as error:  # noqa: BLE001 — report worker failures to the test
            worker_errors.append(error)

    worker = threading.Thread(target=connect_first, daemon=True)
    try:
        worker.start()
        assert first_notification.wait(timeout=5)
        client.close()

        # A different connection now owns the client. Only its notification
        # is valid; the paused first connection must not notify again.
        client.connect()
        assert notifications == [True], (
            "the replacement session must notify before releasing the old callback"
        )

        release_first_notification.set()
        worker.join(timeout=5)

        assert not worker.is_alive()
        assert not worker_errors
        assert notifications == [True], (
            "the superseded session must not emit another success notification"
        )
    finally:
        release_first_notification.set()
        client.close()
        broker.stop()


def test_link_loss_drains_requests_registered_during_shutdown() -> None:
    """A request must not escape pending-map cleanup during link loss."""
    broker = FakeBroker()
    _, client = _client(broker, tag="t-pending-disconnect")
    at_packet_id = threading.Event()
    resume_request = threading.Event()
    packet_id_returned = threading.Event()
    errors: list[Exception] = []

    try:
        client.connect()
        real_next_packet_id = client._next_packet_id
        pending_before_disconnect = client._pending

        # Reconnection must not accidentally make an orphaned request
        # appear successful. Keep the broker unavailable after link loss.
        def offline_socket_factory(host: str, port: int, timeout: float):
            raise OSError("network unavailable")

        client._sock_factory = offline_socket_factory

        def paused_packet_id() -> int:
            at_packet_id.set()
            if not resume_request.wait(timeout=10):
                raise TimeoutError("pending request was not released")
            packet_id = real_next_packet_id()
            packet_id_returned.set()
            return packet_id

        client._next_packet_id = paused_packet_id

        def subscribe() -> None:
            try:
                client.subscribe(["smart/mb/in/dev1"], [1])
            except Exception as error:  # noqa: BLE001 — inspect all worker failures
                # A racing disconnect can legitimately fail a send, but an
                # unexpected exception must never silently pass the test.
                errors.append(error)

        worker = threading.Thread(target=subscribe, daemon=True)
        worker.start()
        assert at_packet_id.wait(timeout=5)

        assert broker.conn is not None
        broker.conn.shutdown(socket.SHUT_RDWR)
        broker.conn.close()

        # Wait until the old reader has actually drained the pending map.
        # Do not rely on sleep or accidentally permit a new connection.
        _wait_for(
            lambda: not client.connected and client._pending is not pending_before_disconnect,
            timeout=5,
        )
        resume_request.set()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert packet_id_returned.is_set(), "the request never passed the paused registration point"
        assert all(isinstance(error, (OSError, ConnectionError)) for error in errors), errors
        assert not client._pending, "a request survived the disconnected session"
    finally:
        resume_request.set()
        client.close()
        broker.stop()
