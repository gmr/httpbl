"""
Tests for the HttpBL Class
"""
__author__ = 'gmr'
__since__ = '6/8/11'

import sys
sys.path.insert(0, '../src')

import httpbl


def test_reverse_ip():
    ip_address = '1.2.3.4'
    expected_response = '4.3.2.1'
    bl = httpbl.HttpBL('test_key')
    response = bl._reverse_ip(ip_address)
    if response != expected_response:
        assert False, "_reverse_ip failed, expected %s but got %s" % \
                      (expected_response, response)

def test_build_query():
    ip_address = '1.2.3.4'
    expected_response = 'test_key.4.3.2.1.dnsbl.httpbl.org'
    bl = httpbl.HttpBL('test_key')
    response = bl._build_query(ip_address)
    if response != expected_response:
        assert False, "_build_query failed, expected %s but got %s" % \
                      (ip_address, expected_response)

def test_decode_ip():

    bl = httpbl.HttpBL('test_key')

    expected_response = {'days_since_last_activity': 0,
                         'name': None,
                         'type': [4, 1],
                         'threat_score': 0}
    response = bl._decode_response('127.0.0.5')
    if response != expected_response:
        assert False, "_decode_response failed, expected %s but got %s" % \
                      (expected_response, response)

    expected_response = {'days_since_last_activity': 0,
                         'name': None,
                         'type': [4, 1],
                         'threat_score': 0}
    response = bl._decode_response('127.0.0.5')
    if response != expected_response:
        assert False, "_decode_response failed, expected %s but got %s" % \
                      (expected_response, response)

    expected_response = {'days_since_last_activity': 0,
                         'name': None,
                         'type': [4, 2],
                         'threat_score': 20}
    response = bl._decode_response('127.0.20.6')
    if response != expected_response:
        assert False, "_decode_response failed, expected %s but got %s" % \
                      (expected_response, response)

    expected_response = {'days_since_last_activity': 10,
                         'name': None,
                         'type': [2],
                         'threat_score': 40}
    response = bl._decode_response('127.10.40.2')
    if response != expected_response:
        assert False, "_decode_response failed, expected %s but got %s" % \
                      (expected_response, response)

    expected_response = {'days_since_last_activity': None,
                         'name': 'Google',
                         'threat_score': None,
                         'type': [0]}
    response = bl._decode_response('127.0.5.0')
    if response != expected_response:
        assert False, "_decode_response failed, expected %s but got %s" % \
                      (expected_response, response)
