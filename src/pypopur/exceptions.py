"""Exceptions raised by pypopur."""


class PopurError(Exception):
    """Base exception for pypopur."""


class ProtocolError(PopurError):
    """A device payload or transport response could not be decoded."""


class TransportError(PopurError):
    """Communication with a device transport failed."""


class TransportDependencyMissing(TransportError):
    """An optional transport dependency is not installed."""


class HandshakeError(TransportError):
    """A local handshake failed without enough evidence to blame credentials."""


class AuthenticationError(TransportError):
    """A transport definitively reported an authentication failure."""


class InvalidLocalKey(AuthenticationError):
    """A transport definitively reported that a device local key is invalid."""


class MissingLocalKey(AuthenticationError):
    """Local control was requested without a per-device local key."""


class UnsupportedCloudAuthentication(PopurError):
    """A transport was asked to perform cloud login that belongs to the account-bootstrap layer."""
