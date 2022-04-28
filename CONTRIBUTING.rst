.. highlight:: shell

Contributing
============
1. Fork the `cryptoconditions`_ repo on GitHub.
2. Clone your fork locally and enter into the project::

    $ git clone git@github.com:your_github_handle/cryptoconditions.git
    $ cd cryptoconditions/

3. Add the ``upstream`` remote::
    
    $ git remote add upstream git@github.com:planetmint/cryptoconditions.git

4. Install in development mode::

    $ pip install -e .[dev]

5. Make sure you can run the tests::

    $ pytest -v

For the installation step and running the tests you can also use the provided
``docker-compose.yml`` file::

    $ docker-compose build
    $ docker-compose run --rm cryptoconditions pytest -v


.. _cryptoconditions: https://github.com/planetmint/cryptoconditions
