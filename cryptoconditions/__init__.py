from cryptoconditions.type_registry import TypeRegistry
from cryptoconditions.types.sha256 import PreimageSha256Fulfillment
from cryptoconditions.types.threshold_sha256 import ThresholdSha256Fulfillment
from cryptoconditions.types.ed25519 import Ed25519Fulfillment
from cryptoconditions.fulfillment import Fulfillment    # noqa: W0611
from cryptoconditions.condition import Condition        # noqa: W0611


TypeRegistry.register_type(PreimageSha256Fulfillment)
TypeRegistry.register_type(ThresholdSha256Fulfillment)
TypeRegistry.register_type(Ed25519Fulfillment)
