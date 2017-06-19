from urllib.parse import parse_qs, urlparse
from hypothesis import given
from hypothesis_regex import regex
from pytest import raises

from cryptoconditions.condition import CONDITION_REGEX

# NOTE: Hardcoding the supported types for now, because fetching them directly
# from the type registry strangely caused a test failure with hypothesis.
# from cryptoconditions import TypeRegistry
# SUPPORTED_TYPES = '$|'.join(t['name'] for t in TypeRegistry.registered_types)
SUPPORTED_TYPES = (
    'preimage-sha-256',
    'prefix-sha-256',
    'threshold-sha-256',
    'rsa-sha-256',
    'ed25519-sha-256',
)


@given(regex(r'^(?!ni$).*:///sha-256;47DEQpj?fpt=preimage-sha-256&cost=0$'))
def test_from_uri_prefix_error(uri):
    from cryptoconditions.condition import Condition, CONDITION_URI_SCHEME
    from cryptoconditions.exceptions import PrefixError
    with raises(PrefixError) as exc_info:
        Condition.from_uri(uri)
    assert exc_info.value.args == (
        'Serialized condition must start with "{}:"'
        .format(CONDITION_URI_SCHEME),)


@given(regex(CONDITION_REGEX))
def test_from_uri_parse_error_missing_fpt(uri):
    from cryptoconditions.condition import Condition
    from cryptoconditions.exceptions import ParsingError
    with raises(ParsingError) as exc_info:
        Condition.from_uri(uri)
    assert exc_info.value.args == (
        'Invalid condition format: "fpt" parameter or value missing.',)


@given(regex(
    r'^ni:\/\/\/sha-256;([a-zA-Z0-9_-]{0,86})\?fpt=preimage-sha-256&(.+)$'))
def test_from_uri_parse_error_missing_cost(uri):
    from cryptoconditions.condition import Condition
    from cryptoconditions.exceptions import ParsingError
    with raises(ParsingError) as exc_info:
        Condition.from_uri(uri)
    assert exc_info.value.args == (
        'Invalid condition format: "cost" parameter or value missing.',)


@given(regex(
    r'^ni:\/\/\/sha-256;([a-zA-Z0-9_-]{0,86})'
    r'\?fpt=preimage-sha-256&cost=[a-z]+$'))
def test_from_uri_parse_error_invalid_cost(uri):
    from cryptoconditions.condition import Condition
    from cryptoconditions.exceptions import ParsingError
    with raises(ParsingError) as exc_info:
        Condition.from_uri(uri)
    assert exc_info.value.args == ('No or invalid cost provided',)


@given(regex(
    r'^ni:\/\/\/sha-256;([a-zA-Z0-9_-]{{0,86}})\?fpt=(?!{})[a-z0-9-]+$'.format(
        '$|'.join(t for t in SUPPORTED_TYPES))))
def test_from_uri_with_unsupported_type(uri):
    from cryptoconditions.condition import Condition
    from cryptoconditions.exceptions import UnsupportedTypeError
    with raises(UnsupportedTypeError) as exc_info:
        Condition.from_uri(uri)
    condition_type = parse_qs(urlparse(uri.rstrip()).query)['fpt'][0]
    assert exc_info.value.args == (
        'Type {} is not supported'.format(condition_type),)
