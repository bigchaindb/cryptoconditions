"""Custom exceptions used in the `cryptoconditions` package.
"""


class ParsingError(Exception):
    """Raised when a URI cannot be parsed"""


class PrefixError(Exception):
    """Raised when a URI's prefix is incorrect."""


class UnsupportedTypeError(Exception):
    """Raised when a unregistered type is used"""


class ValidationError(Exception):
    """Raised when a validation errors out"""


class UnknownEncodingError(Exception):
    """Raised when an unknown or unsuported encoding is used"""


class MissingDataError(Exception):
    """Raised when some data is missing, or not set."""


class ASN1EncodeError(Exception):
    """Raised when an encoding error occurs."""


class ASN1DecodeError(Exception):
    """Raised when a decoding error occurs."""
