Usage
=====
*Yet to be documented.*


ILP Format
----------

Condition
^^^^^^^^^

Conditions are URI encoded as:

.. code-block:: text

    ni:///sha-256;<hashed-fingerprint>?fpt=<condition-type>&cost=<cost>&subtypes=<subtypes>

See https://tools.ietf.org/html/draft-thomas-crypto-conditions-02#section-9.1
for details.

Conditions are binary encoded as:

.. code-block:: text

    Crypto-Conditions DEFINITIONS AUTOMATIC TAGS ::= BEGIN

        -- Conditions

        Condition ::= CHOICE {
          preimageSha256   [0] SimpleSha256Condition,
          prefixSha256     [1] CompoundSha256Condition,
          thresholdSha256  [2] CompoundSha256Condition,
          rsaSha256        [3] SimpleSha256Condition,
          ed25519Sha256    [4] SimpleSha256Condition
        }

        SimpleSha256Condition ::= SEQUENCE {
          fingerprint          OCTET STRING (SIZE(32)),
          cost                 INTEGER (0..4294967295)
        }

        CompoundSha256Condition ::= SEQUENCE {
          fingerprint          OCTET STRING (SIZE(32)),
          cost                 INTEGER (0..4294967295),
          subtypes             ConditionTypes
        }

        ConditionTypes ::= BIT STRING {
          preImageSha256   (0),
          prefixSha256     (1),
          thresholdSha256  (2),
          rsaSha256        (3),
          ed25519Sha256    (4)
        }

    END

See https://tools.ietf.org/html/draft-thomas-crypto-conditions-02#section-7
for details.

Fulfillment
^^^^^^^^^^^
There are no URI encoding rules for fulfillments.

Fulfillments are binary encoded as:

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

See https://tools.ietf.org/html/draft-thomas-crypto-conditions-02#section-7.3
for details.

Condition Types
---------------
*Yet to be documented.*

Preimage-SHA-256
^^^^^^^^^^^^^^^^

Prefix-SHA-256
^^^^^^^^^^^^^^

THRESHOLD-SHA-256
^^^^^^^^^^^^^^^^^

RSA-SHA-256
^^^^^^^^^^^
 
ED25519-SHA-256
^^^^^^^^^^^^^^^
