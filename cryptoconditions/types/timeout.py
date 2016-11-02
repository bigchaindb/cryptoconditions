import re
import time

from datetime import datetime

from cryptoconditions import PreimageSha256Fulfillment

TIMESTAMP_REGEX = r'^\d{10}(\.\d+)?$'


class TimeoutFulfillment(PreimageSha256Fulfillment):
    """ """
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

    def to_dict(self):
        """
        Generate a dict of the fulfillment

        Returns:
            dict: representing the fulfillment
        """
        return {
            'type': 'fulfillment',
            'type_id': self.TYPE_ID,
            'bitmask': self.bitmask,
            'expire_time': self.expire_time.decode()
        }

    def parse_dict(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data (dict): description of the fulfillment

        Returns:
            Fulfillment
        """
        self.preimage = data['expire_time'].encode()

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
    return "{0:.6f}".format(time.time())
