import json
import re
import time

from datetime import datetime

from cryptoconditions import PreimageSha256Fulfillment

TIMESTAMP_REGEX = r'^\d{10}(\.\d+)?$'


class TimeoutFulfillment(PreimageSha256Fulfillment):
    TYPE_ID = 99
    FEATURE_BITMASK = 0x09
    REGEX = TIMESTAMP_REGEX

    def __init__(self, expire_time=None):
        """

        Args:
            expire_time (str): Unix timestamp
        """
        if expire_time and isinstance(expire_time, str) \
                and not re.match(TimeoutFulfillment.REGEX, expire_time):
            raise ValueError('Expire time must be conform UTC unix time, was: {}'.format(expire_time))
        if expire_time:
            super().__init__(expire_time.encode())

    @property
    def expire_time(self):
        """
        """
        return self.preimage

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

    def parse_json(self, json_data):
        """
        Generate fulfillment payload from a json

        Args:
            json_data: json description of the fulfillment

        Returns:
            Fulfillment
        """
        self.preimage = json_data['expire_time'].encode()

    def validate(self, message=None, now=None, **kwargs):
        """
        Check whether this fulfillment meets all validation criteria.

        This will validate the subfulfillments and verify that there are enough
        subfulfillments to meet the threshold.

        Args:
            message (str): message to validate against
            now (str): unix timestamp
        Returns:
            boolean: Whether this fulfillment is valid.
        """

        if not now or not re.match(TimeoutFulfillment.REGEX, now):
            raise ValueError('message must be of unix time format, was: {}'.format(message))
        return float(now) <= float(self.expire_time.decode())


def timestamp():
    """Calculate a UTC timestamp with microsecond precision.

    Returns:
        str: UTC timestamp.

    """
    dt = datetime.utcnow()
    return "{0:.6f}".format(time.mktime(dt.timetuple()) + dt.microsecond / 1e6)
