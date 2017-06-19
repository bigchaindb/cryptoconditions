import hashlib

from cryptoconditions.fulfillment import Fulfillment


class BaseSha256(Fulfillment):
    """ """

    def generate_hash(self):
        """
        Calculate condition hash.

        This method is called internally by ``Condition``. It calculates the
        condition hash by hashing the fingerprint contents.

        Return:
            bytes: Result from hashing the fingerprint contents.
        """
        return hashlib.sha256(self.fingerprint_contents).digest()
