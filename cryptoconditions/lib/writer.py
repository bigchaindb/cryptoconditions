import binascii

from math import ceil


class Writer:
    def __init__(self):
        self.components = []

    def write_uint(self, value, length):
        """
        Write a fixed-length unsigned integer to the stream.

        Args:
            value (int): Value to write. Must be in range for the given length.
            length (int): Number of bytes to encode this value as.
        """
        if not isinstance(value, int):
            raise TypeError('UInt must be an integer')
        elif value < 0:
            raise ValueError('UInt must be positive')
        elif len('{:02b}'.format(value)) > length * 8:
            raise ValueError('UInt {} doesn not fit in {} bytes'
                             .format(value, length))
        buffer = b'\x00'*(length - 1)
        buffer += bytes([value])
        self.write(buffer)

    def write_var_uint(self, value):
        """
        Write a variable length integer to the stream.

        We need to first turn the integer into a buffer in big endian order, then
        we write the buffer as an octet string.

        Args:
            value (int, bytes): Integer to represent.
        """
        if isinstance(value, bytes):
            # If the integer was already passed as a buffer, we can just treat it as an octet string.
            self.write_var_octet_string(value)
        elif not isinstance(value, int):
            raise ValueError('UInt must be an integer')
        elif value < 0:
            raise ValueError('UInt must be positive')

        length_of_value = int(ceil(len('{:02b}'.format(value)) / 8))
        buffer = b'\x00'*(length_of_value - 1)
        buffer += bytes([value])
        self.write_var_octet_string(buffer)

    def write_octet_string(self, buffer, length):
        """
        Write a fixed-length octet string.

        Mostly just a raw write, but this method enforces the length of the provided buffer is correct.

        Args:
            buffer (bytearray, bytes): Data to write.
            length (int): Length of data according to the format.
        """
        if not isinstance(buffer, (bytearray, bytes)):
            raise TypeError('buffer must be of type bytearray')
        if not len(buffer) == length:
            raise ValueError('Incorrect length for octet string (actual: {}, expected: {})'
                             .format(len(buffer), length))
        self.write(buffer)

    def write_var_octet_string(self, buffer):
        """
        Write a variable-length octet string.

        A variable-length octet string is a length-prefixed set of arbitrary bytes.

        Args:
            buffer (Buffer): Contents of the octet string.
        """
        MSB = 0x80

        if len(buffer) <= 127:
            # For buffers shorter than 128 bytes, we simply prefix the length as a single byte.
            self.write_uint8(len(buffer))
        else:
            # For buffers longer than 128 bytes, we first write a single byte containing the length of the length
            # in bytes, with the most significant bit set.
            length_of_length = int(ceil(len('{:02b}'.format(len(buffer))) / 8))
            self.write_uint8(MSB | length_of_length)
            self.write_uint(len(buffer), length_of_length)

        self.write(buffer)

    def write(self, in_bytes):
        """
        Write a series of raw bytes.

        Adds the given bytes to the output buffer.

        Args:
            in_bytes (Buffer): Bytes to write.
        """
        out = in_bytes
        if isinstance(out, (list, bytearray)):
            out = binascii.unhexlify(''.join('{:02x}'.format(x) for x in out))
        if not isinstance(out, bytes):
            out = out.encode('utf-8')
        self.components.append(out)

    @property
    def buffer(self):
        return b''.join(self.components)

    def write_uint8(self, value):
        return self.write_uint(value, 1)

    def write_uint16(self, value):
        return self.write_uint(value, 2)

    def write_uint32(self, value):
        return self.write_uint(value, 4)

    def write_uint64(self, value):
        return self.write_uint(value, 8)
