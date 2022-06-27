Changelog
=========

0.9.11 (2022-06-27)
------------------

* changed the type of license to AGPLv3


0.9.0 (2022-01-27)
------------------

* added zenroom support
* fixed various warnings 


0.8.1 (2021-06-07)
------------------

Changed
^^^^^^^

* Maintenance release.  Updating package dependencies.

0.8.0 (2018-10-20)
------------------

Changed
^^^^^^^

* ``crypto.ed25519_generate_key_pair()`` now supports an optional keyword argument ``seed`` to support deterministic generation
  of a keypair from a seed.
  Example use: ``crypto.ed25519_generate_key_pair(seed=seed_value)``
  Note that the value of ``seed`` must be a 32-byte bytes object.
  Thanks to external contributor @excerebrose for adding this functionality in pull request #487.
* Changed setup.py to use ``PyNaCl~=1.1.0`` again, because 1.2.1 was breaking software that uses the cryptoconditions package.

0.7.3 (2018-09-04)
------------------

Changed
^^^^^^^
* Update setup.py to use ``PyNaCl~=1.2.1``

0.7.2 (2018-08-31)
------------------

Changed
^^^^^^^
* Use `sign` and `verify` instead of deprecated `signer` and `verifier`
for one-shot sign/verify operation using cryptography.

0.7.1 (2018-08-28)
------------------

Changed
^^^^^^^
* Update setup.py to use ``cryptography~=2.3.1``
* Update setup.py to use ``base58~=1.0.0``, also update code using ``base58``
* Licensing info
* README.rst content

Fixed
^^^^^
* Example code in ``examples/ed25519_example.py``: thanks to @Chuseuiti

0.7.0 (2018-02-28)
------------------

Note: The above heading used to say "0.6.0.dev1 (2017-07-06)"
but that was a mistake, because it was added
in commit 9ca4648ef47cc99305d753a337c8ff9db9d80a5a
which contained the message "Update changelog for 0.7.0 release".

Changed
^^^^^^^
* Upgrade to ``pyasn1~=0.4``.


0.6.0.dev1 (2017-07-06)
-----------------------
Fixed
^^^^^
* Add missing import for ``base58``.

0.6.0.dev (2017-06-22)
----------------------
Changed
^^^^^^^
* Upgrade to crypto-conditions version 02:
  https://tools.ietf.org/html/draft-thomas-crypto-cond.

0.5.0 (2016-10-26)
------------------
Changed
^^^^^^^
* Switch to pynacl crypto library for signing and verification with ED25519.


0.4.1 (2016-06-13)
------------------
Fixed
^^^^^
* Timestamp in UTC.

0.4.0 (2016-06-13)
------------------
Changed
^^^^^^^
* Externalize JSON, use dicts internally.

0.3.1 (2016-06-13)
------------------
Added
^^^^^
* Timeout and Inverted Fulfillment.

0.2.2 (2016-04-26)
------------------
Added
^^^^^
* Custom exceptions.

0.2.1 (2016-04-22)
------------------
Added
^^^^^
* Support for JSON.
* ``get_subcondition_from_vk``

Changed
^^^^^^^
* Sync with c31d780 from five-bells-condition.

0.1.6 (2016-04-22)
------------------
Changed
^^^^^^^
* Update cryptoconditions to commit interledgerjs/five-bells-condition@7f21fe7.
