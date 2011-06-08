pyhttpbl
--------
Project Honeypot Http:BL API Package

Requires a Http:BL API key from http://www.projecthoneypot.org/

Example
=======

    import httpbl

    ip_address = '127.5.20.3'
    key = 'my-key'

    bl = httpbl.HttpBL(key)
    response = bl.query(ip_address)

    print "IP Address: %s" % ip_address
    print "Threat Score: %i" % response['threat_score']
    print "Days since last activity: %i" % response['days_since_last_activity']
    print "Visitor type: %s" % ', '.join([httpbl.DESCRIPTIONS[type_] \
                                          for type_ in response['type']])

Response Format
===============

 - days_since_last_activity
 - name
 - threat_score
 - list of visitor types (int)

The list types are enumerated in the module:

 - httpbl.COMMENT_SPAMMER
 - httpbl.HARVESTER
 - httpbl.SEARCH_ENGINE
 - httpbl.SUSPICIOUS

Text descriptions are available in the httpbl.DESCRIPTIONS dictionary.
