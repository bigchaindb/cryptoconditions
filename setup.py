"""
cryptoconditions provide a mechanism to describe a signed
message such that multiple actors in a distributed system
can all verify the same signed message and agree on whether
it matches the description.
"""

from setuptools import setup, find_packages




version = {}
with open('cryptoconditions/version.py') as fp:
    exec(fp.read(), version)

with open('README.rst') as readme_file:
    readme = readme_file.read()


tests_require = [
    'coverage',
    'hypothesis',
    'pep8',
    'pyflakes',
    'pylint',
    'pytest',
    'pytest-cov',
    'pytest-xdist',
    'twine',
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
    name='planetmint-cryptoconditions',
    version=version['__version__'],
    description='Multi-algorithm, multi-level, multi-signature format for '
                'expressing conditions and fulfillments according to the Interledger Protocol (ILP).',
    long_description=readme,
    long_description_content_type='text/x-rst',
    summary="Cryptoconditions as specified by the interledger protocol and extended.",
    keywords="cryptoconditions, interledger, merkle tree, ed25519, threshold signatures, hash lock, zenroom",
    url='https://github.com/planetmint/cryptoconditions/',
    author='Cryptoconditions Contributors',
    author_email='contact@ipdb.global',
    license='MIT',
    zip_safe=True,

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Database',
        'Topic :: Database :: Database Engines/Servers',
        'Topic :: Software Development',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.9',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
    ],

    packages=find_packages(exclude=['tests*', 'examples']),

    install_requires=[
        'zenroom>=2.0.0.dev1644927841',
        'capturer==3.0',
        'base58==2.1.0',
        'PyNaCl==1.4.0',
        'pyasn1==0.4.8',
        'cryptography==3.4.7',
    ],
    setup_requires=['pytest-runner'],
    tests_require=tests_require,
    extras_require={
        'test': tests_require,
        'dev': dev_require + tests_require + docs_require,
        'docs': docs_require,
    },
)
