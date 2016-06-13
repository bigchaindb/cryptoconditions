from cryptoconditions.types.base_sha256 import BaseSha256Fulfillment
from cryptoconditions.lib import Hasher, Reader, Writer, Predictor


class PreimageSha256Fulfillment(BaseSha256Fulfillment):

    TYPE_ID = 0
    FEATURE_BITMASK = 0x03

    def __init__(self, preimage=None):
        """
        PREIMAGE-SHA-256: Hashlock condition using SHA-256.

        This type of condition is also called a hashlock. By creating a hash
        of a difficult-to-guess 256-bit random or pseudo-random integer it
        is possible to create a condition which the creator can trivially
        fulfill by publishing the random value. However, for anyone else,
        the condition is cryptgraphically hard to fulfill, because they
        would have to find a preimage for the given condition hash.

        PREIMAGE-SHA-256 is assigned the type ID 0. It relies on the SHA-256
        and PREIMAGE feature suites which corresponds to a feature bitmask
        of 0x03.

        The preimage is the only input to a SHA256 hashlock condition.

        Note that the preimage should contain enough (pseudo-random) data in order
        to be difficult to guess. A sufficiently large secret seed and a
        cryptographically secure pseudo-random number generator (CSPRNG) can be
        used to avoid having to store each individual preimage.

        Args:
             preimage: Secret data that will be hashed to form the condition.
        """
        if preimage and (not isinstance(preimage, bytes)):
            raise TypeError('Preimage must be bytes, was: {}'.format(preimage))
        self.preimage = preimage

    @property
    def bitmask(self):
        return self.FEATURE_BITMASK

    def write_hash_payload(self, hasher):
        """
        Generate the contents of the condition hash.

        Writes the contents of the condition hash to a Hasher. Used internally by `getCondition`.

        HASH = SHA256(PREIMAGE)

        Args:
             hasher (Hasher): Destination where the hash payload will be written.
        """
        if not isinstance(hasher, Hasher):
            raise TypeError('hasher must be a Hasher instance')
        if self.preimage is None:
            raise ValueError('Could not calculate hash, no preimage provided')
        hasher.write(self.preimage)

    def parse_payload(self, reader, payload_size):
        """
        Parse the payload of a SHA256 hashlock fulfillment.

        Read a fulfillment payload from a Reader and populate this object with that fulfillment.

        FULFILLMENT_PAYLOAD =
            VARBYTES PREIMAGE

        Args:
            reader (Reader): Source to read the fulfillment payload from.
            payload_size (int): Total size of the fulfillment payload.
        """
        if not isinstance(reader, Reader):
            raise TypeError('reader must be a Reader instance')
        self.preimage = reader.read(payload_size)

    def write_payload(self, writer):
        """
        Generate the fulfillment payload.

        This writes the fulfillment payload to a Writer.

        Args:
            writer (Writer): Subject for writing the fulfillment payload.
        """
        if not isinstance(writer, (Writer, Predictor)):
            raise TypeError('writer must be a Writer instance')
        if self.preimage is None:
            raise ValueError('Preimage must be specified')

        writer.write(self.preimage)
        return writer

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
            'preimage': self.preimage.decode()
        }

    def parse_dict(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data (dict): description of the fulfillment

        Returns:
            Fulfillment
        """
        self.preimage = data['preimage'].encode()

    def validate(self, *args, **kwargs):
        """
        Validate this fulfillment.

        For a SHA256 hashlock fulfillment, successful parsing implies that the
        fulfillment is valid, so this method is a no-op.

        Returns:
             boolean: Validation result
        """
        return True
