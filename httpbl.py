"""
Project Honeypot Http:BL API Client

Example:

.. code:: python

    import httpbl

    ip_address = '127.10.20.5'

    print 'Querying {}'.format(ip_address)
    bl = httpbl.HttpBL('my-key')
    print(bl.query(ip_address))

"""
import socket

__version__ = '1.0.1'

DNSBL_SUFFIX = 'dnsbl.httpbl.org.'

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


class HttpBL(object):
    """Query the the Project Honeypot Http:BL API"""

    def __init__(self, key):
        """Initialize the HttpBL object with your Project Honeypot Key

        :param key: Project Honeypot Http:BL Key
        :type key: str

        """
        self.key = key

    def query(self, ip_address):
        """Query the Project Honeypot Http:BL API for the given IP address

        :param ip_address: IP address to query
        :type ip_address: str
        :rtype: dict

        """
        try:
            return self._decode_response(
                socket.gethostbyname(self._build_query(ip_address)))
        except socket.gaierror:  # Not listed
            return {
                'days_since_last_activity': None,
                'name': None,
                'threat_score': 0,
                'type': None
            }

    def _build_query(self, ip_address):
        """Returns the Http:BL query string to use

        :param ip_address: IP address to query
        :type ip_address: str
        :returns: str

        """
        return '{}.{}.{}'.format(
            self.key, self._reverse_ip(ip_address), DNSBL_SUFFIX)

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
        :rtype: dict
        :raises: ValueError

        """
        # Reverse the IP, reassign the octets to integers
        vt, ts, days, rc = [int(o) for o in ip_address.split('.')[::-1]]

        # 127 reflects a valid query response, all others are errors
        if rc != 127:
            raise ValueError('Invalid Response Code: {}'.format(rc))

        # Build a list of visitor types since one IP can be multiple
        visitor_types = []
        if vt & COMMENT_SPAMMER:
            visitor_types.append(COMMENT_SPAMMER)
        if vt & HARVESTER:
            visitor_types.append(HARVESTER)
        if vt & SUSPICIOUS:
            visitor_types.append(SUSPICIOUS)

        # Return the response dictionary
        return {'days_since_last_activity': days if vt else None,
                'name': None if vt else SEARCH_ENGINES[ts],
                'threat_score': ts if vt else None,
                'type': visitor_types if vt else [SEARCH_ENGINE]}
