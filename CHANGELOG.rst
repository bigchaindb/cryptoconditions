Changelog
=========

0.6.0.dev1 (2017-07-06)
-----------------------
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
