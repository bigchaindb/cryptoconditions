from math import ceil


class Predictor:
    def __init__(self):
        self.size = 0

    def write_uint(self, value, length):
        """
        Add one byte to the predicted size.

        Args:
            value (int): Value of integer. Irrelevant here,
                         but included in order to have the same interface as the Writer.
            length (int): Size of integer in bytes.
        """
        self.size += length

    def write_var_uint(self, value):
        """
        Calculate the size of a variable-length integer.

        A VARUINT is a variable length integer encoded as base128 where the highest
        bit indicates that another byte is following. The first byte contains the
        seven least significant bits of the number represented.

        Args:
            value (int): Integer to be encoded
        """

        if isinstance(value, bytes):
            self.write_var_octet_string(value)
        elif not isinstance(value, int):
            raise ValueError('UInt must be an integer')
        elif value < 0:
            raise ValueError('UInt must be positive')

        length = int(ceil(len('{:02b}'.format(value)) / 8))
        self.write_var_octet_string(b'0'*length)

    def write_octet_string(self, value, length):
        """
        Skip bytes for a fixed-length octet string.

        Just an alias for skip. Included to provide consistency with Writer.

        Args:
            value (bytes): Data to write.
            length (int): Length of data according to the format.
        """
        self.skip(length)

    def write_var_octet_string(self, value):
        """
        Calculate the size of a variable-length octet string.

        A variable-length octet string is a length-prefixed set of arbitrary bytes.

        Args:
            value (bytes, int): Contents of the octet string.
        """
        # Skip initial byte
        self.skip(1)

        # Skip separate length field if there is one

        if len(value) > 127:
            length_of_length = int(ceil(len('{:02b}'.format(len(value))) / 8))
            self.skip(length_of_length)
        self.skip(len(value))

    def write(self, in_bytes):
        """
        Pretend to write a series of bytes.

        Args:
            in_bytes (bytes): Bytes to write.
        """
        self.size += len(in_bytes)

    def skip(self, in_bytes):
        """
        Add this many bytes to the predicted size.

        Args:
            in_bytes (int): Number of bytes to pretend to write.
        """
        self.size += in_bytes

    def write_uint8(self, value):
        return self.write_uint(value, 1)

    def write_uint16(self, value):
        return self.write_uint(value, 2)

    def write_uint32(self, value):
        return self.write_uint(value, 4)

    def write_uint64(self, value):
        return self.write_uint(value, 8)

