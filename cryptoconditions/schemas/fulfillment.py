"""ASN.1 definitions for fulfillment objects.

.. code-block:: text

    Crypto-Conditions DEFINITIONS AUTOMATIC TAGS ::= BEGIN

        -- Fulfillments

        Fulfillment ::= CHOICE {
          preimageSha256   [0] PreimageFulfillment ,
          prefixSha256     [1] PrefixFulfillment,
          thresholdSha256  [2] ThresholdFulfillment,
          rsaSha256        [3] RsaSha256Fulfillment,
          ed25519Sha256    [4] Ed25519Sha512Fulfillment
        }

        PreimageFulfillment ::= SEQUENCE {
          preimage             OCTET STRING
        }

        PrefixFulfillment ::= SEQUENCE {
          prefix               OCTET STRING,
          maxMessageLength     INTEGER (0..4294967295),
          subfulfillment       Fulfillment
        }

        ThresholdFulfillment ::= SEQUENCE {
          subfulfillments      SET OF Fulfillment,
          subconditions        SET OF Condition
        }

        RsaSha256Fulfillment ::= SEQUENCE {
          modulus              OCTET STRING,
          signature            OCTET STRING
        }

        Ed25519Sha512Fulfillment ::= SEQUENCE {
          publicKey            OCTET STRING (SIZE(32)),
          signature            OCTET STRING (SIZE(64))
        }

    END

"""
from pyasn1.type import univ
from pyasn1.type.univ import Choice, OctetString, Sequence
from pyasn1.type.namedtype import NamedType, NamedTypes
from pyasn1.type.constraint import ValueRangeConstraint, ValueSizeConstraint
from pyasn1.type.tag import (
    Tag, tagClassContext, tagFormatConstructed, tagFormatSimple)

from .condition import Condition


class Ed25519Sha512Fulfillment(Sequence):

    # TODO implement
    def __deepcopy__(self, memo):
        return None


Ed25519Sha512Fulfillment.componentType = NamedTypes(
    NamedType(
        'publicKey',
        OctetString().subtype(
            subtypeSpec=ValueSizeConstraint(32, 32)).subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 0)),
    ),
    NamedType(
        'signature',
        OctetString().subtype(
            subtypeSpec=ValueSizeConstraint(64, 64)).subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 1)),
    ),
)


class RsaSha256Fulfillment(Sequence):
    pass


RsaSha256Fulfillment.componentType = NamedTypes(
    NamedType(
        'modulus',
        OctetString().subtype(
            implicitTag=Tag(tagClassContext, tagFormatSimple, 0)),
    ),
    NamedType(
        'signature',
        OctetString().subtype(
            implicitTag=Tag(tagClassContext, tagFormatSimple, 1)),
    ),
)


class PreimageFulfillment(Sequence):
    componentType = NamedTypes(
        NamedType('preimage', OctetString().subtype(
            implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
    )


class ThresholdFulfillment(Sequence):
    pass


class PrefixFulfillment(Sequence):
    pass


class Fulfillment(Choice):

    # TODO implement
    def __deepcopy__(self, memo):
        return None


ThresholdFulfillment.componentType = NamedTypes(
    NamedType('subfulfillments', univ.Any()),
    NamedType('subconditions', univ.SetOf(
        componentType=Condition()
    ).subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 1)))
)


PrefixFulfillment.componentType = NamedTypes(
    NamedType(
        'prefix',
        univ.OctetString().subtype(
            implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
    NamedType(
        'maxMessageLength',
        univ.Integer().subtype(
            subtypeSpec=ValueRangeConstraint(0, 4294967295)
        ).subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
    NamedType('subfulfillment', univ.Any()),
)


Fulfillment.componentType = NamedTypes(
    NamedType(
        'preimageSha256',
        PreimageFulfillment().subtype(
            implicitTag=Tag(tagClassContext, tagFormatConstructed, 0))),
    NamedType(
        'prefixSha256',
        PrefixFulfillment().subtype(
            implicitTag=Tag(tagClassContext, tagFormatConstructed, 1))),
    NamedType(
        'thresholdSha256',
        ThresholdFulfillment().subtype(
            implicitTag=Tag(tagClassContext, tagFormatConstructed, 2))),
    NamedType(
        'rsaSha256',
        RsaSha256Fulfillment().subtype(
            implicitTag=Tag(tagClassContext, tagFormatConstructed, 3))),
    NamedType(
        'ed25519Sha256',
        Ed25519Sha512Fulfillment().subtype(
            implicitTag=Tag(tagClassContext, tagFormatConstructed, 4))),
)

PrefixFulfillment.componentType[2]._NamedType__type = Fulfillment().subtype(
    implicitTag=Tag(tagClassContext, tagFormatConstructed, 2))

ThresholdFulfillment.componentType[0]._NamedType__type = univ.SetOf(
    componentType=Fulfillment()
).subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 0))
