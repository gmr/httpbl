httpbl
======
`Project Honeypot <http://www.projecthoneypot.org/>`_ Http:BL API Package

Requires a Http:BL API key from https://www.projecthoneypot.org/

Response Format
---------------

dict with keys:

 - ``days_since_last_activity``
 - ``name``
 - ``threat_score``
 - ``list of visitor types (int)``

The list types are enumerated in the module:

 - ``httpbl.COMMENT_SPAMMER``
 - ``httpbl.HARVESTER``
 - ``httpbl.SEARCH_ENGINE``
 - ``httpbl.SUSPICIOUS``

Text descriptions are available in the ``httpbl.DESCRIPTIONS`` dict.

Example
-------

... code:: python

    import httpbl

    ip_address = '127.5.20.3'
    key = 'my-key'

    bl = httpbl.HttpBL(key)
    response = bl.query(ip_address)

    print('IP Address: {}'.format(ip_address)
    print('Threat Score: {}'.format(response['threat_score'])
    print('Days since last activity: {}'.foramt(response['days_since_last_activity'])
    print('Visitor type: {}'.format(', '.join([httpbl.DESCRIPTIONS[type_]
                                               for type_ in response['type']]))
