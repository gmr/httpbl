"""
Project Honeypot Http:BL API Client

Example:

    import httpbl

    ip_address = '127.10.20.5'
    key = 'my-key'

    print 'Querying %s' % ip_address
    bl = httpbl.HttpBL(key)
    print bl.query(ip_address)

"""
__author__ = 'Gavin M. Roy'
__email__ = 'gmr@myyearbook.com'

import socket

DNSBL_SUFFIX = 'dnsbl.httpbl.org'

# Visitor Types
SEARCH_ENGINE = 0
SUSPICIOUS = 1
HARVESTER = 2
COMMENT_SPAMMER = 4

# List of Search Engines, used to return the name of the search engine
SEARCH_ENGINES = ['Undocumented',
                  'AltaVista',
                  'Ask',
                  'Baidu',
                  'Excite',
                  'Google',
                  'Looksmart',
                  'Lycos',
                  'MSN',
                  'Yahoo',
                  'Cuil',
                  'InfoSeek',
                  'Miscellaneous']

# Text mappings for visitor types
DESCRIPTIONS = {COMMENT_SPAMMER: 'Comment Spammer',
                HARVESTER: 'Harvester',
                SEARCH_ENGINE: 'Search Engine',
                SUSPICIOUS: 'Suspicious'}

# Response for non-listed IP address
_NOT_LISTED = {'days_since_last_activity': None,
               'name': None,
               'threat_score': 0,
               'type': None}

class HttpBL(object):
    """Class based interface for working with the Project Honeypot Http:BL API

    """

    def __init__(self, key):
        """Initialize the HttpBL object with your Project Honeypot Key

        :param key: Project Honeypot Http:BL Key
        :type key: str
        """
        self.key = key

    def _build_query(self, ip_address):
        """Returns the Http:BL query string to use

        :param ip_address: IP address to query
        :type ip_address: str
        :returns: str
        """
        reversed_address = self._reverse_ip(ip_address)
        return '%s.%s.%s' % (self.key, reversed_address, DNSBL_SUFFIX)


    def _reverse_ip(self, ip_address):
        """Take an IP address in 127.0.0.1 format and return it as 1.0.0.127

        :param ip_address: IP address to query
        :type ip_address: str
        :returns: str
        """
        return '.'.join(ip_address.split('.')[::-1])

    def _decode_response(self, ip_address):
        """Decodes a HttpBL response IP and return data structure of response
        data.

        :param ip_address: IP address to query
        :type ip_address: str
        :raises: ValueError
        """
        # Reverse the IP, reassign the octets to integers
        visitor_type, threat_score, days_since_last_activity, response_code = \
            [int(octet) for octet in ip_address.split('.')[::-1]]

        # 127 reflects a valid query response, all others are errors
        if response_code != 127:
            raise ValueError('Invalid Response Code: %i' % response_code)

        # visitor type of 0 reflects a known search engine ip address
        # changing the behavior of the threat_score
        if not visitor_type:
            return {'days_since_last_activity': None,
                    'name': SEARCH_ENGINES[threat_score],
                    'threat_score': None,
                    'type': [SEARCH_ENGINE]}

        # Build a list of visitor types since one IP can be multiple
        visitor_types = []

        if visitor_type & COMMENT_SPAMMER:
            visitor_types.append(COMMENT_SPAMMER)

        if visitor_type & HARVESTER:
            visitor_types.append(HARVESTER)

        if visitor_type & SUSPICIOUS:
            visitor_types.append(SUSPICIOUS)

        # Return the response dictionary
        return {'days_since_last_activity': days_since_last_activity,
                'name': None,
                'threat_score': threat_score,
                'type': visitor_types}

    def query(self, ip_address):
        """Query the Project Honeypot Http:BL API for the given IP address

        :param ip_address: IP address to query
        :type ip_address: str
        """
        query_string = self._build_query(ip_address)

        try:
            response = socket.gethostbyname(query_string)
        except socket.gaierror:
            return NOT_LISTED

        return self._decode_response(response)
