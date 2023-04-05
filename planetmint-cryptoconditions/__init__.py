from planetmint_cryptoconditions.type_registry import TypeRegistry
from planetmint_cryptoconditions.types.preimage import PreimageSha256
from planetmint_cryptoconditions.types.prefix import PrefixSha256
from planetmint_cryptoconditions.types.rsa import RsaSha256
from planetmint_cryptoconditions.types.threshold import ThresholdSha256
from planetmint_cryptoconditions.types.ed25519 import Ed25519Sha256
from planetmint_cryptoconditions.fulfillment import Fulfillment  # noqa: W0611
from planetmint_cryptoconditions.condition import Condition  # noqa: W0611
from planetmint_cryptoconditions.exceptions import ValidationError


TypeRegistry.register_type(PreimageSha256)
TypeRegistry.register_type(PrefixSha256)
TypeRegistry.register_type(ThresholdSha256)
TypeRegistry.register_type(RsaSha256)
TypeRegistry.register_type(Ed25519Sha256)


# Modeled after:
# https://github.com/interledgerjs/five-bells-condition/blob/master/index.js
def validate_condition(serialized_condition):
    condition = Condition.from_uri(serialized_condition)
    return condition.validate()


def validate_fulfillment(serialized_fulfillment, serialized_condition, message=None):
    fulfillment = Fulfillment.from_uri(serialized_fulfillment)
    condition_uri = fulfillment.condition_uri
    if condition_uri != serialized_condition:
        raise ValidationError(
            "Fulfillment does not match condition (expected: {}, actual: {})".format(
                serialized_condition, condition_uri
            )
        )
    return fulfillment.validate(message=message)


def fulfillment_to_condition(serialized_fulfillment):
    fulfillment = Fulfillment.from_uri(serialized_fulfillment)
    return fulfillment.condition_uri


def from_dict(data):
    fulfillment = Fulfillment.from_dict(data)
    return fulfillment
