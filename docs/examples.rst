Examples
========

Preimage Sha 256
----------------

.. code-block:: python

    >>> from planetmint_cryptoconditions import PreimageSha256

    >>> secret = b'Beware! Trying to understand crypto can lead to knowledge intoxications.'

    >>> fulfillment = PreimageSha256(preimage=secret)

    >>> fulfillment.condition_uri
    'ni:///sha-256;xumt48hVcQEXuUx2p2GqVgO4mpq9O_FIYmjb258CkZM?fpt=preimage-sha-256&cost=72'

    >>>  fulfillment.condition_binary
    b'\xa0%\x80 \xc6\xe9\xad\xe3\xc8Uq\x01\x17\xb9Lv\xa7a\xaaV\x03\xb8\x9a\x9a\xbd;\xf1Hbh\xdb\xdb\x9f\x02\x91\x93\x81\x01H'

