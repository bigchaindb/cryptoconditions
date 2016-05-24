import json
import re

from cryptoconditions import PreimageSha256Fulfillment

TIMESTAMP_REGEX = r'^\d{10}(\.\d+)?$'


class TimeoutFulfillment(PreimageSha256Fulfillment):
    TYPE_ID = 99
    FEATURE_BITMASK = 0x09
    REGEX = TIMESTAMP_REGEX

    def __init__(self, expire_time=None):
        """

        Args:
            expire_time (str): Integer threshold
        """
        if expire_time and not re.match(TimeoutFulfillment.REGEX, expire_time):
            raise ValueError('Expire time must be conform UTC unix time, was: {}'.format(expire_time))
        super().__init__(expire_time)

    @property
    def expire_time(self):
        """
        """
        return super().preimage

    def serialize_json(self):
        """
        Generate a JSON object of the fulfillment

        Returns:
        """
        return json.dumps(
            {
                'type': 'fulfillment',
                'type_id': TimeoutFulfillment.TYPE_ID,
                'bitmask': self.bitmask,
                'expire_time': self.expire_time.decode()
            }
        )

    def validate(self, message=None):
        """
        Check whether this fulfillment meets all validation criteria.

        This will validate the subfulfillments and verify that there are enough
        subfulfillments to meet the threshold.

        Args:
            message (str): message to validate against
        Returns:
            boolean: Whether this fulfillment is valid.
        """

        return message <= self.expire_time
