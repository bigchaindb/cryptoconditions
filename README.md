# [![cryptoconditions](media/repo-banner@2x.png)](https://www.bigchaindb.com)

> Multi-algorithm, multi-level, multi-signature format for expressing conditions and fulfillments according to the Interledger Protocol (ILP)

[![Package Status](https://img.shields.io/pypi/v/cryptoconditions.svg)](https://pypi.python.org/pypi/cryptoconditions)
[![Build Status](https://img.shields.io/travis/bigchaindb/cryptoconditions/master.svg)](https://travis-ci.org/bigchaindb/cryptoconditions)
[![Codecov](https://img.shields.io/codecov/c/github/bigchaindb/cryptoconditions/master.svg)](https://codecov.io/github/bigchaindb/cryptoconditions?branch=master)
[![Documentation Status](https://readthedocs.org/projects/cryptoconditions/badge/?version=latest)](http://cryptoconditions.readthedocs.io/en/latest/?badge=latest)


Crypto Conditions
=================

Python implementation of **Crypto-Conditions**. See draft of specification at [draft-thomas-crypto-conditions-02](https://tools.ietf.org/html/draft-thomas-crypto-conditions-02).

The RFC is also on github under
[rfcs/crypto-conditions](https://github.com/rfcs/crypto-conditions).

The Crypto-Conditions specification is part of the
[Interledger Protocol (ILP)](https://interledger.org/rfcs/0003-interledger-protocol/).


Motivation
----------

We would like a way to describe a signed message such that multiple actors in a
distributed system can all verify the same signed message and agree on whether
it matches the description.

This provides a useful primitive for distributed, event-based systems since we
can describe events (represented by signed messages) and therefore define
generic authenticated event handlers.


Installation
------------
To install latest release that is on PyPI:

```bash
$ pip install cryptocondtions
```

Or install from source:

```bash
$ pip install git+https://github.com/bigchaindb/cryptoconditions.git
```

Simple Usage
------------
*Yet to be documented.*

Documentation
-------------
http://cryptoconditions.readthedocs.io/
