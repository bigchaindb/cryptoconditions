import copy

from cryptoconditions.condition import Condition
from cryptoconditions.fulfillment import Fulfillment
from cryptoconditions.fulfillments.base_sha256 import BaseSha256Fulfillment
from cryptoconditions.buffer import Predictor, Reader, Writer


CONDITION = 'condition'
FULFILLMENT = 'fulfillment'


class ThresholdSha256Fulfillment(BaseSha256Fulfillment):
    TYPE_ID = 2
    FEATURE_BITMASK = 0x09

    def __init__(self, threshold=None):
        """
        Create a ThresholdSha256Fulfillment and set the threshold.

        Determines the weighted threshold that is used to consider this condition
        fulfilled. If the added weight of all valid subfulfillments is greater or
        equal to this number, the threshold condition is considered to be fulfilled.

        Args:
            threshold (int): Integer threshold
        """
        self.threshold = threshold
        self.subconditions = []

    def add_subcondition(self, subcondition, weight=1):
        """
        Add a subcondition (unfulfilled).

        This can be used to generate a new threshold condition from a set of
        subconditions or to provide a non-fulfilled subcondition when creating a threshold fulfillment.

        Args:
            subcondition (Condition): Condition to add
            weight (int): Integer weight of the subcondition.
        """
        if not isinstance(subcondition, Condition):
            raise TypeError('Subconditions must be objects of type Condition')
        if not isinstance(weight, int):
            raise ValueError('Invalid weight, not an integer: {}'.format(weight))
        self.subconditions.append(
            {
                'type': CONDITION,
                'body': subcondition,
                'weight': weight
            })

    def add_subfulfillment(self, subfulfillment, weight=1):
        """
        Add a fulfilled subcondition.

        When constructing a threshold fulfillment, this method allows you to
        provide a fulfillment for one of the subconditions.

        Note that you do **not** have to add the subcondition if you're adding the
        fulfillment. The condition can be calculated from the fulfillment and will
        be added automatically.

        Args:
             subfulfillment (Fulfillment): Fulfillment to add
             weight (int): Integer weight of the subcondition.
        """
        if not isinstance(subfulfillment, Fulfillment):
            raise TypeError('Subfulfillments must be objects of type Fulfillment')
        if not isinstance(weight, int):
            raise ValueError('Invalid weight, not an integer: {}'.format(weight))
        self.subconditions.append(
            {
                'type': FULFILLMENT,
                'body': subfulfillment,
                'weight': weight
            })

    @property
    def bitmask(self):
        """
        Get full bitmask.

        This is a type of condition that can contain subconditions. A complete
        bitmask must contain the set of types that must be supported in order to
        validate this fulfillment. Therefore, we need to calculate the bitwise OR
        of this condition's TYPE_BIT and all subcondition's and subfulfillment's bitmasks.

        Returns:
             int: Complete bitmask for this fulfillment.
        """
        bitmask = super().bitmask

        for cond in self.subconditions:
            bitmask |= cond['body'].bitmask

        return bitmask

    def write_hash_payload(self, hasher):
        """
        Produce the contents of the condition hash.

        This function is called internally by the `getCondition` method.

        HASH = SHA256(
            VARUINT TYPE_BIT
            VARUINT THRESHOLD
            VARARRAY
                VARUINT WEIGHT
                CONDITION
        )

        Args:
            hasher (Hasher): Hash generator
        """
        if not len(self.subconditions):
            raise ValueError('Requires subconditions')

        subconditions = []
        for c in self.subconditions:
            # Serialize each subcondition with weight
            writer = Writer()
            writer.write_var_uint(c['weight'])
            writer.write(c['body'].condition.serialize_binary()
                         if c['type'] == FULFILLMENT
                         else c['body'].serialize_binary())
            subconditions.append(b''.join(writer.components))

        # Canonically sort all conditions, first by length, then lexicographically
        sorted_subconditions = ThresholdSha256Fulfillment.sort_buffers(subconditions)

        hasher.write_var_uint(ThresholdSha256Fulfillment.TYPE_ID)
        hasher.write_var_uint(self.threshold)
        hasher.write_var_uint(len(sorted_subconditions))
        for cond in sorted_subconditions:
            hasher.write(cond)
        return hasher

    def calculate_max_fulfillment_length(self):
        """
        Calculates the longest possible fulfillment length.

        In a threshold condition, the maximum length of the fulfillment depends on
        the maximum lengths of the fulfillments of the subconditions. However,
        usually not all subconditions must be fulfilled in order to meet the threshold.

        Consequently, this method relies on an algorithm to determine which
        combination of fulfillments, where no fulfillment can be left out, results
        in the largest total fulfillment size.

        Return:
             int Maximum length of the fulfillment payload

        """
        total_condition_len = 0
        subconditions = []
        for c in self.subconditions:
            condition_len = ThresholdSha256Fulfillment.predict_subcondition_length(c)
            fulfillment_len = ThresholdSha256Fulfillment.predict_subfulfillment_length(c)
            total_condition_len += condition_len
            subconditions.append({
                'weight': c['weight'],
                'size': fulfillment_len - condition_len
            })

        subconditions.sort(key=lambda c: c['weight'])

        worst_case_fulfillments_length = total_condition_len + \
            ThresholdSha256Fulfillment.calculate_worst_case_length(self.threshold, subconditions)

        if worst_case_fulfillments_length == -1:
            raise ValueError('Insufficient subconditions/weights to meet the threshold')

        # Calculate resulting total maximum fulfillment size
        predictor = Predictor()
        predictor.write_var_uint(self.threshold)  # THRESHOLD
        predictor.write_var_uint(len(self.subconditions))
        for c in self.subconditions:
            predictor.write_uint8()  # IS_FULFILLMENT
            predictor.write_var_uint(c['weight'])  # WEIGHT

        # Represents the sum of CONDITION/FULFILLMENT values
        predictor.skip(worst_case_fulfillments_length)

        return predictor.size

    @staticmethod
    def predict_subcondition_length(cond):
        condition_len = len(cond['body'].condition.serialize_binary()) \
            if cond['type'] == FULFILLMENT \
            else len(cond['body'].serialize_binary())

        predictor = Predictor()
        predictor.write_var_uint(cond['weight'])  # WEIGHT
        predictor.write_var_bytes('')  # FULFILLMENT
        predictor.write_var_uint(condition_len)  # CONDITION
        predictor.skip(condition_len)

        return predictor.size

    @staticmethod
    def predict_subfulfillment_length(cond):
        fulfillment_len = cond['body'].condition.max_fulfillment_length \
            if cond['type'] == FULFILLMENT \
            else cond['body'].max_fulfillment_length

        predictor = Predictor()
        predictor.write_var_uint(cond['weight'])  # WEIGHT
        predictor.write_var_uint(fulfillment_len)  # FULFILLMENT
        predictor.skip(fulfillment_len)
        predictor.write_var_bytes('')  # CONDITION

        return predictor.size

    @staticmethod
    def calculate_worst_case_length(threshold, subconditions, index=0):
        """
        * Calculate the worst case length of a set of conditions.
        *
        * This implements a recursive algorithm to determine the longest possible
        * length for a valid, minimal (no fulfillment can be removed) set of
        * subconditions.
        *
        * Note that the input array of subconditions must be sorted by weight
        * descending.
        *
        * The algorithm works by recursively adding and not adding each subcondition.
        * Finally, it determines the maximum of all valid solutions.
        *
        * @author Evan Schwartz <evan@ripple.com>
        *
        * @param {Number} threshold Threshold that the remaining subconditions have
        *   to meet.
        * @param {Object[]} subconditions Set of subconditions.
        * @param {Number} subconditions[].weight Weight of the subcondition
        * @param {Number} subconditions[].size Maximum number of bytes added to the
        *   size if the fulfillment is included.
        * @param {Number} subconditions[].omitSize Maximum number of bytes added to
        *   the size if the fulfillment is omitted (and the condition is added
        *   instead.)
        * @param {Number} [size=0] Size the fulfillment already has (used by the
        *   recursive calls.)
        * @param {Number} [index=0] Current index in the subconditions array (used by
        *   the recursive calls.)
        * @return {Number} Maximum size of a valid, minimal set of fulfillments or
        *   -1 if there is no valid set.
        """
        if threshold <= 0:
            return 0
        elif index < len(subconditions):
            next_condition = subconditions[index]
            return max(
                next_condition['size'] + ThresholdSha256Fulfillment.calculate_worst_case_length(
                    threshold - next_condition['weight'], subconditions, index + 1),
                ThresholdSha256Fulfillment.calculate_worst_case_length(threshold, subconditions, index + 1)
            )
        else:
            return float('-inf')

    def parse_payload(self, reader):
        """
        Parse a fulfillment payload.

        Read a fulfillment payload from a Reader and populate this object with that fulfillment.

        Args:
            reader (Reader): Source to read the fulfillment payload from.
        """
        if not isinstance(reader, Reader):
            raise TypeError('reader must be a Reader instance')
        self.threshold = reader.read_var_uint()

        condition_count = reader.read_var_uint()
        for i in range(condition_count):
            weight = reader.read_var_uint()
            fulfillment = reader.read_var_bytes()
            condition = reader.read_var_bytes()

            if len(fulfillment) and len(condition):
                raise TypeError('Subconditions may not provide both subcondition and fulfillment.')
            elif len(fulfillment):
                self.add_subfulfillment(Fulfillment.from_binary(fulfillment), weight)
            elif len(condition):
                self.add_subcondition(Condition.from_binary(condition), weight)
            else:
                raise TypeError('Subconditions must provide either subcondition or fulfillment.')

    def write_payload(self, writer):
        """
        Generate the fulfillment payload.

        This writes the fulfillment payload to a Writer.

        FULFILLMENT_PAYLOAD =
            VARUINT THRESHOLD
            VARARRAY
                VARUINT WEIGHT
                FULFILLMENT
            VARARRAY
                VARUINT WEIGHT
                CONDITION

        Args:
            writer (Writer): Subject for writing the fulfillment payload.
        """
        if not isinstance(writer, Writer):
            raise TypeError('writer must be a Writer instance')

        subfulfillments = []
        for i, c in enumerate(self.subconditions):
            if c['type'] == FULFILLMENT:
                subfulfillment = c.copy()
                subfulfillment.update(
                    {
                        'index': i,
                        'size': len(c['body'].serialize_binary()),
                        'omit_size': len(c['body'].condition.serialize_binary())
                    }
                )
                subfulfillments.append(subfulfillment)

        smallest_set = \
            ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(self.threshold, subfulfillments)['set']

        optimized_subfulfillments = []
        for i, c in enumerate(self.subconditions):
            # Take minimum set of fulfillments and turn rest into conditions
            if c['type'] == FULFILLMENT and i not in smallest_set:
                subfulfillment = c.copy()
                subfulfillment.update({
                    'type': CONDITION,
                    'body': c['body'].condition
                })
                optimized_subfulfillments.append(subfulfillment)
            else:
                optimized_subfulfillments.append(c)

        serialized_subconditions = []
        for c in optimized_subfulfillments:
            writer_ = Writer()
            writer_.write_var_uint(c['weight'])
            writer_.write_var_bytes(c['body'].serialize_binary() if c['type'] == FULFILLMENT else '')
            # TODO: check if correct
            writer_.write_var_bytes(c['body'].serialize_binary() if c['type'] == CONDITION else '')
            serialized_subconditions.append(b''.join(writer_.components))

        sorted_subconditions = ThresholdSha256Fulfillment.sort_buffers(serialized_subconditions)

        writer.write_var_uint(self.threshold)
        writer.write_var_uint(len(serialized_subconditions))
        for c in sorted_subconditions:
            writer.write(c)

        return writer

    @staticmethod
    def calculate_smallest_valid_fulfillment_set(threshold, fulfillments, state=None):
        """
        * Select the smallest valid set of fulfillments.
        *
        * From a set of fulfillments, selects the smallest combination of
        * fulfillments which meets the given threshold.
        *
        * @param {Number} threshold (Remaining) threshold that must be met.
        * @param {Object[]} fulfillments Set of fulfillments
        * @param {Object} [state] Used for recursion
        * @param {Number} state.index Current index being processed.
        * @param {Number} state.size Size of the binary so far
        * @param {Object[]} state.set Set of fulfillments that were included.
        * @return {Object} Result with size and set properties.
        """
        if not state:
            state = {'index': 0, 'size': 0, 'set': []}

        if threshold <= 0:
            return {'size': state['size'], 'set': state['set']}
        elif state['index'] < len(fulfillments):
            next_fulfillment = fulfillments[state['index']]
            with_next = ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(
                threshold - next_fulfillment['weight'],
                fulfillments,
                {
                    'size': state['size'] + next_fulfillment['size'],
                    'index': state['index'] + 1,
                    'set': state['set'] + [next_fulfillment['index']]
                }
            )

            without_next = ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(
                threshold,
                fulfillments,
                {
                    'size': state['size'] + next_fulfillment['omit_size'],
                    'index': state['index'] + 1,
                    'set': state['set']
                }
            )
            return with_next if with_next['size'] < without_next['size'] else without_next
        else:
            return {'size': float("inf")}

    @staticmethod
    def sort_buffers(buffers):
        """
        * Sort buffers according to spec.
        *
        * Buffers must be sorted first by length. Buffers with the same length are
        * sorted lexicographically.
        *
        * @param {Buffer[]} buffers Set of octet strings to sort.
        * @return {Buffer[]} Sorted buffers.
        """
        buffers_copy = copy.deepcopy(buffers)
        buffers_copy.sort(key=lambda item: (len(item), item))
        return buffers_copy

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
        fulfillments = [c for c in self.subconditions if c['type'] == FULFILLMENT]
        total_weight = sum([f['weight'] for f in fulfillments])
        if total_weight < self.threshold:
            return False
        return all([f['body'].validate(message) for f in fulfillments])
