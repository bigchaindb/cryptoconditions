

class Reader:

    # Most significant bit in a byte
    HIGH_BIT = 0x80

    # Other bits in a byte
    LOWER_SEVEN_BITS = 0x7F

    # Largest integer( in bytes) that is safely representable in JavaScript
    # = > Math.floor(Number.MAX_SAFE_INTEGER.toString(2).length / 8)
    MAX_INT_BYTES = 6

    def __init__(self, buffer):
        self.buffer = buffer
        self.cursor = 0
        self.bookmarks = []

    @staticmethod
    def from_source(source):
        """
        Create a Reader from a source of bytes.

        Currently, this method only allows the creation of a Reader from a Buffer.

        If the object provided is already a Reader, that reader is returned as is.

        Args:
            source (Reader|Buffer): Source of binary data.
        Return:
            Reader: Instance of Reader
        """
        # if (Buffer.isBuffer(source)) {
        # return new Reader(source)
        # } else {
        # throw new Error('Reader must be given a Buffer')
        if isinstance(source, Reader):
            return source
        return Reader(source)

    def bookmark(self):
        """
        Store the current cursor position on a stack.
        """
        self.bookmarks.append(self.cursor)

    def restore(self):
        """
        Pop the most recently bookmarked cursor position off the stack.
        """
        self.cursor = self.bookmarks.pop()

    def ensure_available(self, num_bytes):
        """
        Ensure this number of bytes is buffered.

        This method checks that the given number of bytes is buffered and available
        for reading. If insufficient bytes are available, the method throws an `OverflowError`.

        Args:
            num_bytes (int): Number of bytes that should be available.
        """
        if len(self.buffer) < self.cursor + num_bytes:
            raise OverflowError('Tried to read {} bytes, but only {} bytes available'
                                .format(num_bytes, len(self.buffer) - self.cursor))

    def read_uint(self, length):
        """
        Read a fixed-length big-endian integer.

        Args:
            length (int): Length of the integer in bytes.

        Returns:
            int: Contents of next byte.
        """
        if length > Reader.MAX_INT_BYTES:
            raise OverflowError('Tried too read too large integer (requested: {}, max: {})'
                                .format(length, Reader.MAX_INT_BYTES))
        self.ensure_available(length)
        value = self.buffer[self.cursor:self.cursor+length]
        self.cursor += length
        return int.from_bytes(value, byteorder='big')

    def peek_uint(self, length):
        """
        Look at a fixed-length integer, but don't advance the cursor.

        Args:
            length (int): Length of the integer in bytes.

        Returns:
            int: Contents of the next byte.
        """
        if length > Reader.MAX_INT_BYTES:
            raise OverflowError('Tried too read too large integer (requested: {}, max: {})'
                                .format(length, Reader.MAX_INT_BYTES))
        self.ensure_available(length)
        value = self.buffer[self.cursor:self.cursor+length]
        return int.from_bytes(value, byteorder='big')

    def skip_uint(self, length):
        """
        Advance cursor by length bytes
        """
        self.skip(length)

    def read_var_uint(self):
        """
        Read a variable-length integer at the cursor position.

        Return the integer as a number and advance the cursor accordingly.

        Returns:
            int: Value of the integer.
        """
        buffer = self.read_var_octet_string()
        if len(buffer) > Reader.MAX_INT_BYTES:
            raise OverflowError('UInt of length {} too large to parse as integer(max: {})'
                                .format(len(buffer), Reader.MAX_INT_BYTES))
        return int.from_bytes(buffer[0:len(buffer)], byteorder='big')

    def peek_var_uint(self):
        """
        Read the next variable-length integer, but don't advance the cursor.

        Returns:
            int: Integer at the cursor position.
        """
        self.bookmark()
        value = self.read_var_uint()
        self.restore()

        return value

    def skip_var_uint(self):
        """
        Skip past the variable-length integer at the cursor position.

        Since variable integers are encoded the same way as octet strings,
        this method is equivalent to skipVarOctetString.
        """
        # Read variable integer and ignore output
        self.skip_var_octet_string()

    def read_octet_string(self, length):
        """
        Read a fixed-length octet string.

        Args:
            length (int): Length of the octet string.
        """
        return self.read(length)

    def peek_octet_string(self, length):
        """
        Peek at a fixed length octet string.

        Args:
            length (int): Length of the octet string.
        """
        return self.peek(length)

    def skip_octet_string(self, length):
        """
        Skip a fixed length octet string.

        Args:
            length (int): Length of the octet string.
        """
        return self.skip(length)

    def read_length_prefix(self):
        """
        Read a length prefix.

        You shouldn't need this. Length prefixes are used internally by variable-length octet strings and integers.

        Returns:
            int: Length value.
        """
        length = self.read_uint8()
        if length & Reader.HIGH_BIT:
            return self.read_uint(length & Reader.LOWER_SEVEN_BITS)
        return length

    def read_var_octet_string(self):
        """
        Read a variable-length octet string.

        A variable-length octet string is a length-prefixed set of arbitrary bytes.

        @return {Buffer} Contents of the octet string.
        """
        length = self.read_length_prefix()

        return self.read(length)

    def peek_var_octet_string(self):
        """
        * Read a variable-length buffer, but do not advance cursor position.
        *
        * @return {Buffer} Contents of the buffer.
        """

        self.bookmark()
        value = self.read_var_octet_string()
        self.restore()

        return value

    def skip_var_octet_string(self):
        """
        Skip a variable-length buffer.
        """
        length = self.read_length_prefix()
        return self.skip(length)

    def read(self, num_bytes):
        """
        Read a given number of bytes.

        Returns this many bytes starting at the cursor position and advances the
        cursor.

        Args:
            num_bytes (int): Number of bytes to read.

        Return:
            Contents of bytes read.
        """
        self.ensure_available(num_bytes)

        value = self.buffer[self.cursor:self.cursor + num_bytes]
        self.cursor += num_bytes

        return value

    def peek(self, num_bytes):
        """
        Read bytes, but do not advance cursor.

        Args:
             num_bytes (int): Number of bytes to read.

        Return:
            Contents of bytes read.
        """

        self.ensure_available(num_bytes)

        return self.buffer.slice(self.cursor, self.cursor + num_bytes)

    def skip(self, num_bytes):
        """
        Skip a number of bytes.

        Advances the cursor by this many bytes.

        Args:
             num_bytes (int): Number of bytes to advance the cursor by.
        """
        self.ensure_available(num_bytes)

        self.cursor += num_bytes

    def read_uint8(self):
        return self.read_uint(1)

    def read_uint16(self):
        return self.read_uint(2)

    def read_uint32(self):
        return self.read_uint(4)

    def read_uint64(self):
        return self.read_uint(8)

    def peek_uint8(self):
        return self.peek_uint(1)

    def peek_uint16(self):
        return self.peek_uint(2)

    def peek_uint32(self):
        return self.peek_uint(4)

    def peek_uint64(self):
        return self.peek_uint(8)

    def skip_uint8(self):
        return self.skip_uint(1)

    def skip_uint16(self):
        return self.skip_uint(2)

    def skip_uint32(self):
        return self.skip_uint(4)

    def skip_uint64(self):
        return self.skip_uint(8)
