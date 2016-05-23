"""
cryptoconditions provide a mechanism to describe a signed
message such that multiple actors in a distributed system
can all verify the same signed message and agree on whether
it matches the description.
"""

from setuptools import setup, find_packages

tests_require = [
    'pytest',
    'coverage',
    'pep8',
    'pyflakes',
    'pylint',
    'pytest',
    'pytest-cov',
    'pytest-xdist',
]

dev_require = [
    'ipdb',
    'ipython',
]

docs_require = [
    'recommonmark>=0.4.0',
    'Sphinx>=1.3.5',
    'sphinxcontrib-napoleon>=0.4.4',
    'sphinx-rtd-theme>=0.1.9',
]

setup(
    name='cryptoconditions',
    version='0.2.3',
    description='Multi-algorithm, multi-level, multi-signature format for '
                'expressing conditions and fulfillments according to the Interledger Protocol (ILP).',
    long_description=__doc__,
    summary="Cryptoconditions as specified by the interledger protocol",
    keywords="cryptoconditions, interledger, merkle tree, ed25519, threshold signatures, hash lock",
    url='https://github.com/bigchaindb/cryptoconditions/',
    author='Cryptoconditions Contributors',
    author_email='dev@bigchaindb.com',
    license='MIT',
    zip_safe=True,

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Database',
        'Topic :: Database :: Database Engines/Servers',
        'Topic :: Software Development',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
    ],

    packages=find_packages(exclude=['tests*', 'examples']),

    install_requires=[
        'base58==0.2.2',
        'ed25519',
    ],
    setup_requires=['pytest-runner'],
    tests_require=tests_require,
    extras_require={
        'test': tests_require,
        'dev':  dev_require + tests_require + docs_require,
        'docs':  docs_require,
    },
)

