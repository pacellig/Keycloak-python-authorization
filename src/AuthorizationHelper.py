#!/usr/bin/env python
"""
Created on 18/11/18
Author pacellig

Helper class to deal with JWT exchanged with keycloak.
"""
from keycloak import KeycloakOpenID, exceptions as keycloak_exceptions
import jwt
from functools import wraps
from flask import request, Response
from pprint import pprint
import ConfigParser
import io
import requests


class AuthorizationHelper:
    def __init__(self, config_file):
        # Get configurations, load everything here to make code easier to read
        self.config_file = config_file
        self.config = None
        self.server_url = None
        self.auth_server_url = None
        self.realm_name = None
        self.protected_client_id = None
        self.keycloak_public_key = None
        self.client_secret_key = None
        self.auth_enabled = None
        self.grant_type = None
        self.client_id = None
        self.username = None
        self.password = None
        self.load_configurations()

        # Set up openid connector
        self.keycloak_openid = KeycloakOpenID(server_url=self.auth_server_url,
                                              client_id=self.protected_client_id,
                                              realm_name=self.realm_name,
                                              client_secret_key=self.client_secret_key)

    def load_configurations(self):
        """
        Load all the needed configurations from configuration file.
        :return:
        """
        with open(self.config_file) as f:
            configs = f.read()
        config = ConfigParser.RawConfigParser(allow_no_value=True)
        config.readfp(io.BytesIO(configs))
        self.config = config
        self.auth_enabled = config.getboolean("authorization", "auth_enabled")
        self.server_url = config.get("keycloak", "url")
        self.auth_server_url = config.get("authorization", "auth_server_url")
        self.realm_name = config.get("authorization", "realm_name")
        self.protected_client_id = config.get("authorization", "protected_client_id")
        self.keycloak_public_key = config.get("authorization", "realm_public_key")
        self.client_secret_key = config.get("authorization", "protected_client_secret_key")
        self.grant_type = str(config.get("token-client", "grant_type"))
        self.client_id = str(config.get("token-client", "client_id"))
        self.username = str(config.get("token-client", "username"))
        self.password = str(config.get("token-client", "password"))

    def verify_jwt(self, access_token):
        """
        Verify that the JWT (access_token) can be decoded using the related client_id and public_key.
        :param access_token:
        :return: True or False
        """
        try:
            # Build the key in format accepted by JWT (python implementation)
            header = "-----BEGIN PUBLIC KEY-----\n"
            trailer = "\n-----END PUBLIC KEY-----"
            key = header + str(self.keycloak_public_key).encode('utf-8') + trailer
            # Decode the token by using the server public key
            decoded = jwt.decode(access_token, key=key,
                                 algorithms=['RS256'],
                                 audience=self.protected_client_id)
            return True, decoded
        except Exception as e:
            print e
            return False, e

    def login_required(self, f):
        """
        Create a decorator for the exposed endpoints.
        :param f:
        :return:
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Perform verification on authorization only if that's enabled in the configurations.
            if self.auth_enabled:
                try:
                    token_header = request.headers['Authorization']
                    if not token_header:
                        return Response(status=401, response="Unauthorized")
                    else:
                        # Verify JWT token is valid
                        decoded_token = self.verify_jwt(token_header)
                        if decoded_token[0]:
                            pprint(decoded_token[1])
                            return f(*args, **kwargs)
                        else:
                            return Response(status=401, response=str(decoded_token[1]))
                except Exception as e:
                    return Response(status=401, response=str(e))
            else:
                return f(*args, **kwargs)
        return decorated_function

    def get_user_token(self):
        """
        Retrieve the access token for the user from the dedicated client.
        :return: access_token
        """
        url = self.auth_server_url + "realms/" + self.realm_name + "/protocol/openid-connect/token"
        payload = "grant_type=" + self.grant_type + "&client_id=" + self.client_id + "&username=" + \
                  self.username + "&password=" + self.password
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        response = requests.request("POST", url, data=payload, headers=headers)

        return response.json()['access_token']
