import hashlib
import binascii

from cryptoconditions.lib.writer import Writer


class Hasher(Writer):

    def __init__(self, algorithm):
        if algorithm == 'sha256':
            self.hash = hashlib.sha256()
        else:
            raise NotImplementedError
        super().__init__()

    def write(self, in_bytes):
        """
        Adds bytes to the hash input.
        
        The hasher will pass these bytes into the hashing function. By overriding
        the Writer class and implementing this method, the Hasher supports any of
        the datatypes that a Writer can write.
        
        Args:
            in_bytes (Buffer): Bytes to add to the hash.
        """
        out = in_bytes
        if isinstance(out, (list, bytearray)):
            out = binascii.unhexlify(''.join('{:02x}'.format(x) for x in out))
        if not isinstance(out, bytes):
            out = out.encode('utf-8')
        self.hash.update(out)

    def digest(self):
        """
        Return the hash.

        Returns the finished hash based on what has been written to the Hasher so far.

        Return:
            Buffer: Resulting hash.
        """
        return self.hash.digest()

    @staticmethod
    def length(algorithm):
        """
        Get digest length for hashing algorithm.

        Args:
            algorithm (string): Hashing algorithm identifier.

        Return:
            int: Digest length in bytes.
        """
        return len(Hasher(algorithm).digest())


