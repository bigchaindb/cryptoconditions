from cryptoconditions import ThresholdSha256Fulfillment

CONDITION = 'condition'
FULFILLMENT = 'fulfillment'


class InvertedThresholdSha256Fulfillment(ThresholdSha256Fulfillment):
    """ """
    TYPE_ID = 98
    FEATURE_BITMASK = 0x09

    def validate(self, message=None, **kwargs):
        """
        Check whether this fulfillment meets all validation criteria.

        This will validate the subfulfillments and verify that there are enough
        subfulfillments to meet the threshold.

        Args:
            message (str): message to validate against
        Returns:
            boolean: Whether this fulfillment is valid.
        """
        return not super().validate(message, **kwargs)
