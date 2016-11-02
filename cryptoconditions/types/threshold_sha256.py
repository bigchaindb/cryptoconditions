import copy
from cryptoconditions.condition import Condition
from cryptoconditions.fulfillment import Fulfillment
from cryptoconditions.types.ed25519 import Ed25519Fulfillment
from cryptoconditions.lib import Predictor, Reader, Writer
from cryptoconditions.types.base_sha256 import BaseSha256Fulfillment

CONDITION = 'condition'
FULFILLMENT = 'fulfillment'


class ThresholdSha256Fulfillment(BaseSha256Fulfillment):
    """ """
    TYPE_ID = 2
    FEATURE_BITMASK = 0x09

    def __init__(self, threshold=None):
        """
        THRESHOLD-SHA-256: Threshold gate condition using SHA-256.

        Threshold conditions can be used to create m-of-n multi-signature groups.

        Threshold conditions can represent the AND operator by setting the threshold
        to equal the number of subconditions (n-of-n) or the OR operator by setting the thresold to one (1-of-n).

        Threshold conditions allows each subcondition to carry an integer weight.

        Since threshold conditions operate on conditions, they can be nested as well
        which allows the creation of deep threshold trees of public keys.

        By using Merkle trees, threshold fulfillments do not need to to provide the
        structure of unfulfilled subtrees. That means only the public keys that are
        actually used in a fulfillment, will actually appear in the fulfillment, saving space.

        One way to formally interpret threshold conditions is as a boolean weighted
        threshold gate. A tree of threshold conditions forms a boolean weighted
        threhsold circuit.

        THRESHOLD-SHA-256 is assigned the type ID 2. It relies on the SHA-256 and
        THRESHOLD feature suites which corresponds to a feature bitmask of 0x09.

        Threshold determines the weighted threshold that is used to consider this condition
        fulfilled. If the added weight of all valid subfulfillments is greater or
        equal to this number, the threshold condition is considered to be fulfilled.

        Args:
            threshold (int): Integer threshold
        """
        if threshold and (not isinstance(threshold, int) or threshold < 1):
            raise ValueError('Threshold must be a integer greater than zero, was: {}'.format(threshold))
        self.threshold = threshold
        self.subconditions = []

    def add_subcondition(self, subcondition, weight=1):
        """
        Add a subcondition (unfulfilled).

        This can be used to generate a new threshold condition from a set of
        subconditions or to provide a non-fulfilled subcondition when creating a threshold fulfillment.

        Args:
            subcondition (Condition, str): Condition to add
            weight (int): Integer weight of the subcondition.
        """
        if isinstance(subcondition, str):
            subcondition = Condition.from_uri(subcondition)
        elif not isinstance(subcondition, Condition):
            raise TypeError('Subconditions must be URIs or objects of type Condition')
        if not isinstance(weight, int) or weight < 1:
            raise ValueError('Invalid weight: {}'.format(weight))
        self.subconditions.append(
            {
                'type': CONDITION,
                'body': subcondition,
                'weight': weight
            })

    def add_subcondition_uri(self, subcondition_uri):
        """
        Add a subcondition (unfulfilled).

        This will automatically parse the URI and call addSubcondition.

        Args:
            subcondition_uri (str): Subcondition URI.
        """
        if not isinstance(subcondition_uri, str):
            raise TypeError('Subcondition must be provided as a URI string, was {}'.format(subcondition_uri))
        self.add_subcondition(Condition.from_uri(subcondition_uri))

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
        if isinstance(subfulfillment, str):
            subfulfillment = Fulfillment.from_uri(subfulfillment)
        elif not isinstance(subfulfillment, Fulfillment):
            raise TypeError('Subfulfillments must be URIs or objects of type Fulfillment')
        if not isinstance(weight, int) or weight < 1:
            # TODO: Add a more helpful error message.
            raise ValueError('Invalid weight: {}'.format(weight))
        self.subconditions.append(
            {
                'type': FULFILLMENT,
                'body': subfulfillment,
                'weight': weight
            })

    def add_subfulfillment_uri(self, subfulfillment_uri):
        """
        Add a fulfilled subcondition.

        This will automatically parse the URI and call addSubfulfillment.

        Args:
            subfulfillment_uri (str): Subfulfillment URI.
        """
        if not isinstance(subfulfillment_uri, str):
            raise TypeError('Subfulfillment must be provided as a URI string, was: {}'.format(subfulfillment_uri))
        self.add_subfulfillment(Fulfillment.from_uri(subfulfillment_uri))

    @property
    def bitmask(self):
        """
        Get full bitmask.

        This is a type of condition that can contain subconditions. A complete
        bitmask must contain the set of types that must be supported in order to
        validate this fulfillment. Therefore, we need to calculate the bitwise OR
        of this condition's FEATURE_BITMASK and all subcondition's and subfulfillment's bitmasks.

        Returns:
             int: Complete bitmask for this fulfillment.
        """
        bitmask = super().bitmask

        for cond in self.subconditions:
            bitmask |= cond['body'].bitmask

        return bitmask

    def get_subcondition_from_vk(self, vk):
        """
        Retrieve the subcondition or fulfillment for a certain verifying key

        Args:
            vk (str, bytes): base58 representation of the verifying key

        Returns:
            Ed25519Fulfillment, Condition: a Ed25519Fulfillment with the vk
        """
        if isinstance(vk, str):
            vk = vk.encode()

        conditions = []
        for c in self.subconditions:
            if isinstance(c['body'], Ed25519Fulfillment) and c['body'].public_key.encode(encoding='base58') == vk:
                conditions.append(c['body'])
            elif isinstance(c['body'], ThresholdSha256Fulfillment):
                result = c['body'].get_subcondition_from_vk(vk)
                if result is not None:
                    conditions += result
        return conditions

    def write_hash_payload(self, hasher):
        """
        Produce the contents of the condition hash.

        This function is called internally by the
        :meth:`~cryptoconditions.fulfillment.Fulfillment.condition` property.

        .. code-block:: none

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
            # write_weight(writer, c['weight'])
            writer.write_var_uint(c['weight'])
            writer.write(c['body'].condition_binary
                         if c['type'] == FULFILLMENT
                         else c['body'].serialize_binary())
            subconditions.append(writer.buffer)

        # Canonically sort all conditions, first by length, then lexicographically
        sorted_subconditions = ThresholdSha256Fulfillment.sort_buffers(subconditions)

        hasher.write_uint32(self.threshold)
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
             int: Maximum length of the fulfillment payload

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

        subconditions.sort(key=lambda x: abs(x['weight']))

        worst_case_fulfillments_length = total_condition_len + \
            ThresholdSha256Fulfillment.calculate_worst_case_length(self.threshold, subconditions)

        if worst_case_fulfillments_length == float('-inf'):
            raise ValueError('Insufficient subconditions/weights to meet the threshold')

        # Calculate resulting total maximum fulfillment size
        predictor = Predictor()
        predictor.write_uint32(self.threshold)             # threshold
        predictor.write_var_uint(len(self.subconditions))  # count
        for c in self.subconditions:
            predictor.write_uint8(None)                        # presence bitmask
            if not c['weight'] == 1:
                # write_weight(predictor, c['weight'])
                predictor.write_var_uint(c['weight'])      # weight

        # Represents the sum of CONDITION/FULFILLMENT values
        predictor.skip(worst_case_fulfillments_length)

        return predictor.size

    @staticmethod
    def predict_subcondition_length(cond):
        return len(cond['body'].condition_binary) \
            if cond['type'] == FULFILLMENT \
            else len(cond['body'].serialize_binary())

    @staticmethod
    def predict_subfulfillment_length(cond):
        fulfillment_len = cond['body'].condition.max_fulfillment_length \
            if cond['type'] == FULFILLMENT \
            else cond['body'].max_fulfillment_length

        predictor = Predictor()
        predictor.write_uint16(None)                       # type
        predictor.write_var_octet_string(b'0' * fulfillment_len)  # payload

        return predictor.size

    @staticmethod
    def calculate_worst_case_length(threshold, subconditions, index=0):
        """
        Calculate the worst case length of a set of conditions.

        This implements a recursive algorithm to determine the longest possible
        length for a valid, minimal (no fulfillment can be removed) set of subconditions.

        Note that the input array of subconditions must be sorted by weight descending.

        The algorithm works by recursively adding and not adding each subcondition.
        Finally, it determines the maximum of all valid solutions.

        Author:
            Evan Schwartz <evan@ripple.com>

        Args:
            threshold (int): Threshold that the remaining subconditions have to meet.
            subconditions (:obj:`list` of :class:`~cryptoconditions.condition.Condition`): Set of subconditions.

                * ``subconditions[].weight`` Weight of the subcondition
                * ``subconditions[].size`` Maximum number of bytes added to the
                  size if the fulfillment is included.
                * ``subconditions[].omitSize`` Maximum number of bytes added to
                  the size if the fulfillment is omitted (and the
                  condition is added instead.)

            index (int): Current index in the subconditions array (used by the recursive calls.)

        Returns:
            int: Maximum size of a valid, minimal set of fulfillments or -inf if there is no valid set.
        """
        if threshold <= 0:
            return 0
        elif index < len(subconditions):
            next_condition = subconditions[index]
            return max(
                next_condition['size'] + ThresholdSha256Fulfillment.calculate_worst_case_length(
                    threshold - abs(next_condition['weight']), subconditions, index + 1),
                ThresholdSha256Fulfillment.calculate_worst_case_length(threshold, subconditions, index + 1)
            )
        else:
            return float('-inf')

    def parse_payload(self, reader, *args):
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
            # reader, weight = read_weight(reader)
            fulfillment = reader.read_var_octet_string()
            condition = reader.read_var_octet_string()

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

        .. code-block:: none

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
                        'omit_size': len(c['body'].condition_binary)
                    }
                )
                subfulfillments.append(subfulfillment)

        # FIXME: KeyError due to returned `{'size': inf}` when self.threshold > len(subfulfillments)
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
            # writer_ = write_weight(writer_, c['weight'])
            writer_.write_var_uint(c['weight'])
            writer_.write_var_octet_string(c['body'].serialize_binary() if c['type'] == FULFILLMENT else '')
            writer_.write_var_octet_string(c['body'].serialize_binary() if c['type'] == CONDITION else '')
            serialized_subconditions.append(writer_.buffer)

        sorted_subconditions = ThresholdSha256Fulfillment.sort_buffers(serialized_subconditions)

        writer.write_var_uint(self.threshold)
        writer.write_var_uint(len(sorted_subconditions))
        for c in sorted_subconditions:
            writer.write(c)

        return writer

    @staticmethod
    def calculate_smallest_valid_fulfillment_set(threshold, fulfillments, state=None):
        """
        Select the smallest valid set of fulfillments.

        From a set of fulfillments, selects the smallest combination of
        fulfillments which meets the given threshold.

        Args:
            threshold (int): (Remaining) threshold that must be met.
            fulfillments ([{}]): Set of fulfillments
            state (dict): Used for recursion
                          state.index (int): Current index being processed.
                          state.size (int): Size of the binary so far
                          state.set ([{}]): Set of fulfillments that were included.
        Returns:
            (dict): Result with size and set properties.
        """
        if not state:
            state = {'index': 0, 'size': 0, 'set': []}

        if threshold <= 0:
            return {'size': state['size'], 'set': state['set']}
        elif state['index'] < len(fulfillments):
            next_fulfillment = fulfillments[state['index']]
            with_next = ThresholdSha256Fulfillment.calculate_smallest_valid_fulfillment_set(
                threshold - abs(next_fulfillment['weight']),
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
        Sort buffers according to spec.

        Buffers must be sorted first by length. Buffers with the same length are sorted lexicographically.

        Args:
            buffers ([]): Set of octet strings to sort.

        Returns:
            Sorted buffers.
        """
        buffers_copy = copy.deepcopy(buffers)
        buffers_copy.sort(key=lambda item: (len(item), item))
        return buffers_copy

    def to_dict(self):
        """
        Generate a dict of the fulfillment

        Returns:
            dict: representing the fulfillment
        """
        subfulfillments = []
        for c in self.subconditions:
            subcondition = c['body'].to_dict()
            subcondition.update({'weight': c['weight']})
            subfulfillments.append(subcondition)

        return {
            'type': 'fulfillment',
            'type_id': self.TYPE_ID,
            'bitmask': self.bitmask,
            'threshold': self.threshold,
            'subfulfillments': subfulfillments
        }

    def parse_dict(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data (dict): description of the fulfillment

        Returns:
            Fulfillment
        """
        if not isinstance(data, dict):
            raise TypeError('reader must be a dict instance')
        self.threshold = data['threshold']

        for subfulfillments in data['subfulfillments']:
            weight = subfulfillments['weight']

            if subfulfillments['type'] == FULFILLMENT:
                self.add_subfulfillment(Fulfillment.from_dict(subfulfillments), weight)
            elif subfulfillments['type'] == CONDITION:
                self.add_subcondition(Condition.from_dict(subfulfillments), weight)
            else:
                raise TypeError('Subconditions must provide either subcondition or fulfillment.')

    def validate(self, message=None, **kwargs):
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

        # Find total weight and smallest individual weight
        min_weight = float('inf')
        total_weight = 0
        for fulfillment in fulfillments:
            min_weight = min(min_weight, abs(fulfillment['weight']))
            total_weight += min_weight

        # Total weight must meet the threshold
        if total_weight < self.threshold:
            # Threshold not met
            return False

        # TODO: Discuss with ILP
        # But the set must be minimal, there mustn't be any fulfillments we could take out
        # if self.threshold + min_weight <= total_weight:
        #     # Fulfillment is not minimal
        #     return False
        # TODO: ILP specs see unfulfilled conditions as conditions and not fulfillments
        valid_decisions = []
        for fulfillment in fulfillments:
            if fulfillment['body'].validate(message, **kwargs):
                valid_decisions += [True] * fulfillment['weight']
        return len(valid_decisions) >= self.threshold
