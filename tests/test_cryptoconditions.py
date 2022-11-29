import pytest


def test_validate_condition(minimal_ed25519):
    from planetmint_cryptoconditions import validate_condition

    assert validate_condition(minimal_ed25519.condition_uri) is True


def test_validate_fulfillment(minimal_ed25519):
    from planetmint_cryptoconditions import validate_fulfillment

    assert (
        validate_fulfillment(minimal_ed25519.fulfillment, minimal_ed25519.condition_uri, minimal_ed25519.message)
        is True
    )


def test_validate_fulfillment_condition_mismatch(minimal_ed25519, minimal_preimage):
    from planetmint_cryptoconditions import validate_fulfillment
    from planetmint_cryptoconditions.exceptions import ValidationError

    with pytest.raises(ValidationError):
        validate_fulfillment(minimal_ed25519.fulfillment, minimal_preimage.condition_uri)


def test_fulfillment_to_condition(minimal_ed25519):
    from planetmint_cryptoconditions import fulfillment_to_condition

    assert fulfillment_to_condition(minimal_ed25519.fulfillment) == minimal_ed25519.condition_uri


def test_from_dict(minimal_ed25519):
    from planetmint_cryptoconditions import from_dict
    from planetmint_cryptoconditions.fulfillment import Fulfillment

    fulfillment = Fulfillment.from_uri(minimal_ed25519.fulfillment)
    fulfillment_from_dict = from_dict(fulfillment.to_dict())
    assert fulfillment_from_dict.condition_uri == fulfillment.condition_uri
