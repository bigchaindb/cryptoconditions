Usage
=====

Cryptoconditions consist of a simple conecept: 'conditions' need to be 'fulfilled' in order to be accepted.
Several types on conditions exists. The fulfillment of a condition depends on its type and comes in different requirements.

An overview of different condition types and their corresponding fulfillments is given in the following paragraphs and sections.
The formal definition can be found in the `formal definitions in the cryptocondition draft <https://tools.ietf.org/doc/html/draft-thomas-crypto-conditions-03#section-7.3>`_

Conditions & Fulfillments Types
-------------------------------
The following condition & fulfillment pairs exist:

- Ed25519-SHA256

- Prefix-SHA256

- Preimage-SHA-256

- Rsa-SHA256

- Threshold-SHA-256

- Zenroom-SHA-256 

The Zenroom-SHA-256 condition & fulfillment is explained in more detail. Please have a look at the unit tests
at `cryptoconditions <https://github.com/planetmint/cryptoconditions/tree/main/tests/types>`_, Ed25519-SHA256 and Threshold-SHA-256 examples are listed there.



ZENROOM-SHA-256
^^^^^^^^^^^^^^^^^

The 'ZenroomSha256' Condition/Fulfillment is created by the following set of data: a script, keys and data.

* the 'script' is that script that needs to be fulfilled/is exeuged

* the keys are the keys that are used by the script

* the data object is a JSON object with data that is used and addressed by the script


The fulfillment (e.g. the script/policy/contract) can be signed-off by a script:

* the message to be signed e.g. the transaction

* the conditional script that fulfills the fulfillment

* a set of private keys that has to be of size greater than 0

Sample fulfillment:

.. code-block:: python

    fulfill_script = """
    Scenario 'ecdh': Bob verifies the signature from Alice
    Given I have a 'ecdh public key' from 'Alice'
    Given that I have a 'string dictionary' named 'houses'
    Given I have a 'signature' named 'signature'
    When I verify the 'houses' has a signature in 'signature' by 'Alice'
    Then print the string 'ok'
    """

Sample condition:

.. code-block:: python

    condition_script = """
      Scenario 'ecdh': create the signature of an object
      Given I have the 'keyring'
      Given that I have a 'string dictionary' named 'houses'
      When I create the signature of 'houses'
      Then print the 'signature'
      """

The message being signed is required to be a JSON document and needs to contain the following set of data:

* message containing the input tag with the 'houses' object 

.. code-block:: JSON

    "input": {
        "houses": [
            {
                "name": "Harry",
                "team": "Gryffindor",
            },
            {
                "name": "Draco",
                "team": "Slytherin",
            },
        ],
    }

* message output tag containing the output data (e.g. result of calling the sign-method)

.. code-block:: JSON

    "output": {"output": ["ok"]}
  

..
  ED25519-SHA-256
  ^^^^^^^^^^^^^^^

  Preimage-SHA-256
  ^^^^^^^^^^^^^^^^

  Prefix-SHA-256
  ^^^^^^^^^^^^^^

  RSA-SHA-256
  ^^^^^^^^^^^

  THRESHOLD-SHA-256
  ^^^^^^^^^^^^^^^^^
