from itertools import chain

from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from cryptoconditions.condition import Condition
from cryptoconditions.exceptions import MissingDataError, ValidationError
from cryptoconditions.fulfillment import Fulfillment
from cryptoconditions.types.ed25519 import Ed25519Sha256
from cryptoconditions.types.base_sha256 import BaseSha256
from cryptoconditions.schemas.fingerprint import ThresholdFingerprintContents

CONDITION = 'condition'
FULFILLMENT = 'fulfillment'


class ThresholdSha256(BaseSha256):
    """ """
    TYPE_ID = 2
    TYPE_NAME = 'threshold-sha-256'
    TYPE_ASN1 = 'thresholdSha256'
    TYPE_ASN1_CONDITION = 'thresholdSha256Condition'
    TYPE_ASN1_FULFILLMENT = 'thresholdSha256Fulfillment'
    TYPE_CATEGORY = 'compound'

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
        if threshold is not None and (
                not isinstance(threshold, int) or threshold < 1):
            raise ValueError(
                'Threshold must be a integer greater than zero, was: {}'.
                format(threshold)
            )
        self.threshold = threshold
        self.subconditions = []

    def add_subcondition(self, subcondition):
        """
        Add a subcondition (unfulfilled).

        This can be used to generate a new threshold condition from a set
        of subconditions or to provide a non-fulfilled subcondition when
        creating a threshold fulfillment.

        Args:
            subcondition (:class:`~cryptoconditions.condition.Condition` or :obj:`str`):
                Condition object or URI string representing a new
                subcondition to be added.

        """
        if isinstance(subcondition, str):
            subcondition = Condition.from_uri(subcondition)
        elif not isinstance(subcondition, Condition):
            raise TypeError('Subconditions must be URIs or objects of type Condition')
        self.subconditions.append({'type': CONDITION, 'body': subcondition})

    def add_subfulfillment(self, subfulfillment):
        """
        Add a fulfilled subcondition.

        When constructing a threshold fulfillment, this method allows you to
        provide a fulfillment for one of the subconditions.

        Note that you do **not** have to add the subcondition if you're
        adding the fulfillment. The condition can be calculated from the
        fulfillment and will be added automatically.

        Args:
            subfulfillment (:class:`~cryptoconditions.fulfillment.Fulfillment or :obj:`str`):
                Fulfillment object or URI string representing a new
                subfulfillment to be added.

        """
        if isinstance(subfulfillment, str):
            subfulfillment = Fulfillment.from_uri(subfulfillment)
        elif not isinstance(subfulfillment, Fulfillment):
            raise TypeError('Subfulfillments must be URIs or objects of type Fulfillment')
        self.subconditions.append(
            {'type': FULFILLMENT, 'body': subfulfillment})

    @property
    def asn1_dict_payload(self):
        subfulfillments = sorted(
            (sf for sf in self.subconditions if sf['type'] == FULFILLMENT),
            key=lambda x: x['body'].calculate_cost(),
        )
        subconditions = sorted(
            (sc for sc in self.subconditions if sc['type'] == CONDITION),
            key=lambda x: x['body'].cost,
        )
        if len(subfulfillments) < self.threshold:
            raise ValidationError('Not enough fulfillments')

        minimal_fulfillments = subfulfillments[:self.threshold]
        remaining_conditions = chain(
            (c['body'] for c in subconditions),
            (sf['body'].condition for sf in subfulfillments[self.threshold:]),
        )
        # TODO sort by binary repr
        SF = [{mf['body'].TYPE_ASN1: mf['body'].asn1_dict_payload}
              for mf in minimal_fulfillments]
        SC = [rc.to_asn1_dict() for rc in remaining_conditions]
        return {'subfulfillments': SF, 'subconditions': SC}

    @property
    def fingerprint_contents(self):
        """

        .. todo:: docs

        """
        subconditions = [
            c.to_asn1_dict() for c in sorted(
                map(lambda c: c['body']
                    if isinstance(c['body'], Condition)
                    else c['body'].condition, self.subconditions))
        ]
        asn1_fingerprint_obj = nat_decode(
            {'threshold': self.threshold, 'subconditions': subconditions},
            asn1Spec=ThresholdFingerprintContents(),
        )
        return der_encode(asn1_fingerprint_obj)

    @property
    def subtypes(self):
        """Complete set of types for this fulfillment.

        This is a type of condition that can contain subconditions. A
        complete set of subtypes must contain all types that must be
        supported in order to validate this fulfillment. Therefore, we
        need to join the type of this fulfillment with all of the sets
        of subtypes for each of the subconditions.

        Note:
            Never include our own type as a subtype. The reason is that
            we already know that the validating implementation knows how
            to interpret this type, otherwise it wouldn't be able to
            verify this fulfillment to begin with.

        """
        return {
            t for s in self.subconditions
            for t in chain(s['body'].subtypes, (s['body'].type_name,))
            if t != ThresholdSha256.TYPE_NAME
        }

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
            if isinstance(c['body'], Ed25519Sha256) and c['body'].public_key == vk:
                conditions.append(c['body'])
            elif isinstance(c['body'], ThresholdSha256):
                result = c['body'].get_subcondition_from_vk(vk)
                if result is not None:
                    conditions += result
        return conditions

    @staticmethod
    def get_subcondition_cost(subcondition):
        return (subcondition['body'].condition.cost
                if subcondition['type'] == FULFILLMENT
                else subcondition['body'].cost)

    @staticmethod
    def calculate_worst_case_length(threshold, subcondition_costs):
        """
        Calculate the worst case cost of a set of subconditions.

        Given a set of costs ``C`` and a threshold ``t``, it returns the
        sum of the largest ``t`` elements in ``C``.

        Args:
            threshold (int): Threshold that the remaining subconditions
                have to meet.
            subcondition_costs (:obj:`list` of :class:`~cryptoconditions.condition.Condition`):
                Set of subconditions.

        Returns:
            int: Maximum cost of a valid, minimal set of fulfillments or
            -inf if there is no valid set.

        """
        if len(subcondition_costs) < threshold:
            return float('-inf')
        return sum(sorted(subcondition_costs)[-threshold:])

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
            with_next = ThresholdSha256.calculate_smallest_valid_fulfillment_set(
                threshold - abs(next_fulfillment['weight']),
                fulfillments,
                {
                    'size': state['size'] + next_fulfillment['size'],
                    'index': state['index'] + 1,
                    'set': state['set'] + [next_fulfillment['index']]
                }
            )

            without_next = ThresholdSha256.calculate_smallest_valid_fulfillment_set(
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

    def calculate_cost(self):
        """Calculate length of longest fulfillments."""
        subcondition_costs = [
            ThresholdSha256.get_subcondition_cost(s)
            for s in self.subconditions
        ]

        worst_case_fulfillments_cost = ThresholdSha256.\
            calculate_worst_case_length(self.threshold, subcondition_costs)

        if worst_case_fulfillments_cost == float('-inf'):
            raise MissingDataError(
                'Insufficient number of subconditions to meet the threshold')

        return worst_case_fulfillments_cost + 1024 * len(subcondition_costs)

    def to_dict(self):
        """
        Generate a dict of the fulfillment

        Returns:
            dict: representing the fulfillment
        """
        subfulfillments = []
        for c in self.subconditions:
            subcondition = c['body'].to_dict()
            subfulfillments.append(subcondition)

        return {
            'type': ThresholdSha256.TYPE_NAME,
            'threshold': self.threshold,
            'subfulfillments': subfulfillments
        }

    def to_asn1_dict(self):
        return {self.TYPE_ASN1: self.asn1_dict_payload}

    def parse_json(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data (dict): description of the fulfillment

        Returns:
            Fulfillment
        """
        self.threshold = data['threshold']
        for subfulfillment in data.get('subfulfillments', ()):
            self.add_subfulfillment(Fulfillment.from_json(subfulfillment))
        for subcondition in data.get('subconditions', ()):
            self.add_subcondition(Condition.from_json(subcondition))

    def parse_dict(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data (dict): description of the fulfillment

        Returns:
            Fulfillment
        """
        self.threshold = data['threshold']
        for subfulfillments in data.get('subfulfillments', ()):
            self.add_subfulfillment(Fulfillment.from_dict(subfulfillments))
        for subconditions in data.get('subconditions', ()):
            self.add_subcondition(Condition.from_dict(subfulfillments))

    def parse_asn1_dict_payload(self, data):
        self.threshold = len(data['subfulfillments'])
        for subfulfillment in data['subfulfillments']:
            self.subconditions.append({
                'type': FULFILLMENT,
                'body': Fulfillment.from_asn1_dict(subfulfillment),
            })
        for subcondition in data['subconditions']:
            self.subconditions.append({
                'type': CONDITION,
                'body': Condition.from_asn1_dict(subcondition),
            })

    # TODO See if kwargs is really necessary.
    # If yes document it. If not remove it.
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

        # Number of fulfilled conditions must meet the threshold
        if len(fulfillments) < self.threshold:
            raise ValidationError('Threshold not met')

        # But the set must be minimal, there mustn't be any fulfillments
        # we could take out
        if len(fulfillments) > self.threshold:
            raise ValidationError('Fulfillment is not minimal')

        return all(
            fulfillment['body'].validate(message=message)
            for fulfillment in fulfillments
        )
