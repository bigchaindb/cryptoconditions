.. image:: https://badge.fury.io/py/planetmint-cryptoconditions.svg
        :target: https://badge.fury.io/py/planetmint-cryptoconditions

.. image:: https://app.travis-ci.com/planetmint/cryptoconditions.svg?branch=main
        :target: https://app.travis-ci.com/planetmint/cryptoconditions

.. image:: https://codecov.io/gh/planetmint/cryptoconditions/branch/main/graph/badge.svg?token=2Bo1knLW0Q
        :target: https://codecov.io/gh/planetmint/cryptoconditions
    
The cryptoconditions Package
============================

A Python implementation of the Crypto-Conditions spec: a multi-algorithm, multi-level, multi-signature format for expressing conditions and fulfillments.

This implementation doesn't implement the entire Crypto-Conditions spec. It implements the conditions needed by Planetmint, and some others. It's compliant with `version 02 <https://tools.ietf.org/html/draft-thomas-crypto-conditions-02>`_ and `version 04 <https://tools.ietf.org/html/draft-thomas-crypto-conditions-03>`_ of the spec.


See also: 

* the `rfcs/crypto-conditions repository <https://github.com/rfcs/crypto-conditions>`_

Pre-conditions
--------------

Cryptoconditions require a Python version above 3.8.

Installation
------------

To install latest release from PyPI:

.. code-block:: bash

    $ pip install planetmint-cryptoconditions

Documentation
-------------
Public documentation is available at `https://docs.planetmint.io/projects/cryptoconditions/ <https://docs.planetmint.io/projects/cryptoconditions/en/latest/>`_.


Development
-----------
This project uses `poetry <https://python-poetry.org/>` for dependency management.
Run `poetry install` to start local development.
