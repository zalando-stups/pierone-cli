============
Pier One CLI
============

.. image:: https://travis-ci.org/zalando-stups/pierone-cli.svg?branch=master
   :target: https://travis-ci.org/zalando-stups/pierone-cli
   :alt: Build Status

.. image:: https://coveralls.io/repos/zalando-stups/pierone-cli/badge.svg
   :target: https://coveralls.io/r/zalando-stups/pierone-cli
   :alt: Code Coverage

.. image:: https://img.shields.io/pypi/dw/stups-pierone.svg
   :target: https://pypi.python.org/pypi/stups-pierone/
   :alt: PyPI Downloads

.. image:: https://img.shields.io/pypi/v/stups-pierone.svg
   :target: https://pypi.python.org/pypi/stups-pierone/
   :alt: Latest PyPI version

.. image:: https://img.shields.io/pypi/l/stups-pierone.svg
   :target: https://pypi.python.org/pypi/stups-pierone/
   :alt: License

Convenience command line tool for Pier One Docker registry.

.. code-block:: bash

    $ sudo pip3 install --upgrade stups-pierone

Usage
=====

.. code-block:: bash

    $ pierone login
    $ pierone teams

See the `STUPS documentation on pierone`_ for details.

You can also run it locally from source:

.. code-block:: bash

    $ python3 -m pierone

Running Unit Tests
==================

.. code-block:: bash

    $ python3 setup.py test --cov-html=true

.. _STUPS documentation on pierone: http://stups.readthedocs.org/en/latest/components/pierone.html

Releasing
=========

.. code-block:: bash

    $ ./release.sh <NEW-VERSION>
