"""
Tests for the HttpBL Class
"""
import socket
import unittest

import mock

import httpbl


class HttpBLTestCase(unittest.TestCase):
    def setUp(self):
        self.bl = httpbl.HttpBL('test_key')

    @mock.patch('socket.gethostbyname')
    def test_not_listed(self, method):
        method.side_effect = socket.gaierror
        self.assertDictEqual(
            self.bl.query('127.0.0.1'), {
                'days_since_last_activity': None,
                'name': None,
                'threat_score': 0,
                'type': None})

    def test_reverse_ip(self):
        self.assertEqual(self.bl._reverse_ip('1.2.3.4'), '4.3.2.1')

    def test_build_query(self):
        self.assertEqual(
            self.bl._build_query('1.2.3.4'),
            'test_key.4.3.2.1.dnsbl.httpbl.org.')

    def test_decode_response(self):
        tests = {
            '127.0.0.5': {
                'days_since_last_activity': 0,
                'name': None,
                'type': [4, 1],
                'threat_score': 0
            },
            '127.0.20.6': {
                'days_since_last_activity': 0,
                'name': None,
                'type': [4, 2],
                'threat_score': 20
            },
            '127.10.40.2': {
                'days_since_last_activity': 10,
                'name': None,
                'type': [2],
                'threat_score': 40
            },
            '127.0.5.0': {
                'days_since_last_activity': None,
                'name': 'Google',
                'threat_score': None,
                'type': [0]
            }
        }
        for ipaddr, expectation in tests.items():
            self.assertDictEqual(self.bl._decode_response(ipaddr), expectation)

    def test_decode_invalid_response(self):
        with self.assertRaises(ValueError):
            self.bl._decode_response('172.0.0.1')
