from urllib.parse import parse_qs, urlparse

from hypothesis import given
from hypothesis.strategies import from_regex
from pytest import raises

from planetmint_cryptoconditions.condition import CONDITION_REGEX

# NOTE: Hardcoding the supported types for now, because fetching them directly
# from the type registry strangely caused a test failure with hypothesis.
# from planetmint_cryptoconditions import TypeRegistry
# SUPPORTED_TYPES = '$|'.join(t['name'] for t in TypeRegistry.registered_types)
SUPPORTED_TYPES = (
    "preimage-sha-256",
    "prefix-sha-256",
    "threshold-sha-256",
    "rsa-sha-256",
    "ed25519-sha-256",
)


@given(from_regex(r"^(?!ni$).*:///sha-256;47DEQpj?fpt=preimage-sha-256&cost=0$"))
def test_from_uri_prefix_error(uri):
    from planetmint_cryptoconditions.condition import Condition, CONDITION_URI_SCHEME
    from planetmint_cryptoconditions.exceptions import PrefixError

    with raises(PrefixError) as exc_info:
        Condition.from_uri(uri)
    assert exc_info.value.args == ('Serialized condition must start with "{}:"'.format(CONDITION_URI_SCHEME),)


@given(from_regex(CONDITION_REGEX))
def test_from_uri_parse_error_missing_fpt(uri):
    from planetmint_cryptoconditions.condition import Condition
    from planetmint_cryptoconditions.exceptions import ParsingError

    with raises(ParsingError) as exc_info:
        Condition.from_uri(uri)
    assert exc_info.value.args == ('Invalid condition format: "fpt" parameter or value missing.',)


@given(from_regex(r"^ni:\/\/\/sha-256;([a-zA-Z0-9_-]{0,86})\?fpt=preimage-sha-256&(.+)$"))
def test_from_uri_parse_error_missing_cost(uri):
    from planetmint_cryptoconditions.condition import Condition
    from planetmint_cryptoconditions.exceptions import ParsingError

    with raises(ParsingError) as exc_info:
        Condition.from_uri(uri)
    assert exc_info.value.args == ('Invalid condition format: "cost" parameter or value missing.',)


@given(from_regex(r"^ni:\/\/\/sha-256;([a-zA-Z0-9_-]{0,86})" r"\?fpt=preimage-sha-256&cost=[a-z]+$"))
def test_from_uri_parse_error_invalid_cost(uri):
    from planetmint_cryptoconditions.condition import Condition
    from planetmint_cryptoconditions.exceptions import ParsingError

    with raises(ParsingError) as exc_info:
        Condition.from_uri(uri)
    assert exc_info.value.args == ("No or invalid cost provided",)


@given(
    from_regex(
        r"^ni:\/\/\/sha-256;([a-zA-Z0-9_-]{{0,86}})\?fpt=(?!{})[a-z0-9-]+$".format(
            "$|".join(t for t in SUPPORTED_TYPES)
        )
    )
)
def test_from_uri_with_unsupported_type(uri):
    from planetmint_cryptoconditions.condition import Condition
    from planetmint_cryptoconditions.exceptions import UnsupportedTypeError

    with raises(UnsupportedTypeError) as exc_info:
        Condition.from_uri(uri)
    condition_type = parse_qs(urlparse(uri.rstrip()).query)["fpt"][0]
    assert exc_info.value.args == ("Type {} is not supported".format(condition_type),)


@given(from_regex(r"^ni:\/\/\/sha-265;([a-zA-Z0-9_-]{0,86})\?(.+)$"))
def test_from_uri_malformed_uri(uri):
    from planetmint_cryptoconditions.condition import Condition
    from planetmint_cryptoconditions.exceptions import ParsingError

    # Note that the uri will contain `sha-265` instead of `sha-256`
    with raises(ParsingError):
        Condition.from_uri(uri)


def test_from_uri_invalid_arguments(minimal_ed25519):
    from planetmint_cryptoconditions.condition import Condition

    # raises a TypeError if the serialized_condition is not a str
    with raises(TypeError):
        Condition.from_uri(1)

    # Note: This should be removed in future versions of the code
    # from uri will return the the condition instance if we pass it a
    # condition instance
    condition = Condition.from_uri(minimal_ed25519.condition_uri)
    assert Condition.from_uri(condition) == condition


def test_condition_comparison(minimal_ed25519, minimal_prefix):
    from planetmint_cryptoconditions.condition import Condition

    assert Condition.from_uri(minimal_ed25519.condition_uri) == Condition.from_uri(minimal_ed25519.condition_uri)

    assert not Condition.from_uri(minimal_ed25519.condition_uri) == Condition.from_uri(minimal_prefix.condition_uri)


def test_condition_hash():
    from planetmint_cryptoconditions.condition import Condition

    condition = Condition()

    # raises an exception if hash is not 32 bytes long
    with raises(ValueError):
        condition.hash = "a"

    # raises a ValueError if the hash is not set
    with raises(ValueError):
        condition.hash

    # correctly set the hash
    condition.hash = "a" * 32
    assert condition.hash == "a" * 32


def test_condition_cost():
    from planetmint_cryptoconditions.condition import Condition

    condition = Condition()

    # raises a ValueError if the cost is not an int
    condition.cost = "a"
    with raises(ValueError):
        condition.cost


def test_condition_validate():
    from planetmint_cryptoconditions.condition import Condition

    # lets set a known type_id so that the TypeRegistry can return the correct
    # condition type
    condition = Condition()
    condition.type_id = 0

    # subtypes can have at most 32 bits or else raise a value error
    condition.subtypes = range(Condition.MAX_SAFE_SUBTYPES + 1)
    with raises(ValueError):
        condition.validate()

    # raises a ValueError if there is unsuported subtype
    condition.subtypes = set(["magic"])
    with raises(ValueError):
        condition.validate()

    # raises a ValueError if the cost if higher than MAX_COST
    condition.subtypes = set()
    condition.cost = Condition.MAX_COST + 1
    with raises(ValueError):
        condition.validate()


def test_condition_to_asn1_json(basic_threshold):
    from planetmint_cryptoconditions.condition import Condition
    from planetmint_cryptoconditions.type_registry import TypeRegistry

    condition = Condition.from_uri(basic_threshold.condition_uri)
    condition_type = TypeRegistry.find_by_type_id(condition.type_id)

    assert condition.to_asn1_json() == {
        "type": condition_type["asn1_condition"],
        "value": {"cost": basic_threshold.cost, "fingerprint": condition.hash, "subtypes": "01011"},
    }
