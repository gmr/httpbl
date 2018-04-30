httpbl
======
`Project Honeypot <http://www.projecthoneypot.org/>`_ Http:BL API Package

Requires a Http:BL API key from https://www.projecthoneypot.org/

|Version| |Status| |Coverage| |License|

Response Format
---------------

dict with keys:

- ``days_since_last_activity``
- ``name``
- ``threat_score``
- ``types`` - a list of visitor types (``int`` values)

The list types are enumerated in the module:

- ``httpbl.COMMENT_SPAMMER``
- ``httpbl.HARVESTER``
- ``httpbl.SEARCH_ENGINE``
- ``httpbl.SUSPICIOUS``

Text descriptions are available in the ``httpbl.DESCRIPTIONS`` dict.

Example
-------

.. code:: python

    import httpbl

    ip_address = '127.5.20.3'

    bl = httpbl.HttpBL('my-key')
    response = bl.query(ip_address)

    print('IP Address: {}'.format(ip_address)
    print('Threat Score: {}'.format(response['threat_score'])
    print('Days since last activity: {}'.foramt(response['days_since_last_activity'])
    print('Visitor type: {}'.format(', '.join([httpbl.DESCRIPTIONS[t] for t in response['type']]))

.. |Version| image:: https://img.shields.io/pypi/v/httpbl.svg?
   :target: https://pypi.python.org/pypi/httpbl

.. |Status| image:: https://img.shields.io/travis/gmr/httpbl.svg?
   :target: https://travis-ci.org/gmr/httpbl

.. |Coverage| image:: https://img.shields.io/codecov/c/github/gmr/httpbl.svg?
   :target: https://codecov.io/github/gmr/httpbl?branch=master

.. |License| image:: https://img.shields.io/github/license/gmr/httpbl.svg?
   :target: https://github.com/gmr/httpbl
