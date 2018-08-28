Changelog
=========

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
