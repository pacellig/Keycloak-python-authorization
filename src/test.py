#!/usr/bin/env python
"""
Created on 18/11/18
Author pacellig

Basic test suite for the application.

##################################################################################################
# Warning : Make sure keycloak is up and running at the url indicated in the configuration file. #
##################################################################################################
"""
import requests
import unittest
import ConfigParser
import io
from AuthorizationHelper import AuthorizationHelper

config = None
authorization_helper = AuthorizationHelper('../config/config-authorization.ini')


def load_config(config_file):
    """
    Load the configuration handler in global variable.
    :param config_file:
    :return:
    """
    global config
    with open(config_file) as f:
        configs = f.read()
    config = ConfigParser.RawConfigParser(allow_no_value=True)
    config.readfp(io.BytesIO(configs))


def make_authorized_request(url):
    """
    Attempt to connect to protected endpoint using a valid access_token.
    :return: status_code
    """
    token = authorization_helper.get_user_token()
    headers = {
        'Authorization': token
    }
    response = requests.request("GET", url, headers=headers)
    return response.status_code


def make_unauthorized_request(url):
    """
    Attempt to connect to protected endpoint NOT using a valid access_token.
    :return: status_code
    """
    response = requests.request("GET", url)
    return response.status_code


class TestSuite(unittest.TestCase):
    def test_authorized_request_ok(self):
        url = "http://127.0.0.1:55774/protected"
        self.assertEqual(make_authorized_request(url), 200)

    def test_unauthorized_request(self):
        url = "http://127.0.0.1:55774/protected"
        self.assertEqual(make_unauthorized_request(url), 401)

    def test_unsafe_endpoint(self):
        """
        Teh unsafe endpoint should always be accessible.
        :return:
        """
        url = "http://127.0.0.1:55774/unsafe"
        self.assertEqual(make_authorized_request(url), 200)
        self.assertEqual(make_unauthorized_request(url), 200)


def main():
    load_config('../config/config-authorization.ini')
    unittest.main()


if __name__ == '__main__':
    main()
