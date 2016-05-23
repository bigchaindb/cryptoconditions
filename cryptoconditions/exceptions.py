"""Custom exceptions used in the `cryptoconditions` package.
"""


class ParsingError(Exception):
    """Raised when a URI cannot be parsed"""


class UnsupportedTypeError(Exception):
    """Raised when a unregistered type is used"""


class ValidationError(Exception):
    """Raised when a validation errors out"""
