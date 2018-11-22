#!/usr/bin/env python
"""
Created on 18/11/18
Author pacellig

Very simple flask app exposing endpoints for demonstration purposes.
"""
from flask import Flask, Response
from AuthorizationHelper import AuthorizationHelper

app = Flask(__name__)

ah = AuthorizationHelper('../config/config-authorization.ini')


@app.route('/protected', methods=['GET'])
@ah.login_required
def resource_get():
    return Response(status=200, response="User is authorized to access this endpoint.")


@app.route('/unsafe', methods=['GET'])
def unsafe_endpoint():
    return Response(status=200, response="This endpoint is publicly accessible.")


if __name__ == '__main__':
    app.run(debug=True, port=55774)
