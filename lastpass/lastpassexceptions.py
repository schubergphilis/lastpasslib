class ApiLimitReached(Exception):
    """Server responded with a 429 status."""


class InvalidMfa(Exception):
    """The mfa token provided is invalid."""


class InvalidPassword(Exception):
    """The password provided is invalid."""


class InvalidYubiKey(Exception):
    """The yubikey token provided is invalid."""


class MfaRequired(Exception):
    """A mfa token is required but not provided."""


class ServerError(Exception):
    """Server responded with some error."""


class UnknownUsername(Exception):
    """The username provided is not known to the server."""


class UnexpectedResponse(Exception):
    """The response provided does not follow the expected format."""
