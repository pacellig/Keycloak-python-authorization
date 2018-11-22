# Secure REST endpoint using Keycloak and JWT

## Keycloak environment setup

Download Keycloak from [https://www.keycloak.org/downloads.html](https://www.keycloak.org/downloads.html) (N.B. Version 4.6.0.Final has been used when writing this guide, on Ubuntu 18.04.1 LTS).
Run a Keycloak instance with 
```bash
~/keycloak-4.6.0.Final/bin/standalone.sh
```

The admin interface is running (by default) at [http://127.0.0.1:8080](http://127.0.0.1:8080)

On the first access, create admin user:

Admin credentials:
> usr: admin          
> pwd: adminKtest15$

A configuration file for keycloak (with realms, clients and users used in the following) is available in /keycloak-app-configs as realm-export.json.
In order to use it:

1. Download /keycloak-app-configs/realm-export.json
2. In the keycloak welcome page hoover over master, then choose Add realm
3. Import the realm from the downloaded file 

The environment should be up and running, with the proper configurations.
In the following sections (Realm, Client, Users) more details can be found about how the setup has been performed. 

### Realm

Create realm testRealm

* Copy realm RS256 public key in config-authorization.ini

### Client (Representing application to be secured)
Create client:

* ClientID: testClientAPI
* Client protocol: OpenID Connect
* Access type: bearer-only
* Authorization enabled: ON

##### Client Credentials

* Client Authenticator: Client ID and Secret
* Regenerate Secret: 
* * Secret: d438d34e-3a86-4026-bb05-b3e3c4966e10 (To be copied in ./config/config-authorization.ini)

### Client (The one providing the access tokens)
Create client:

* CLientID: testGetTokenClient
* Client protocol: OpenID Connect
* Access type: public
* Authorization enabled: OFF
* Valid redirect URIs: http://localhost


### Users 
Create a simple user `testuser`

testUser credentials:
> usr: testuser      
> pwd: user123

## Endpoints APP

### Requirements
The application has been developed using Python 2.7.15rc1
In order to fulfill the requirements, open a shell and run
```bash
cd src
pip install -r requirements.txt
```
    
## Run the app

The app exposing the endpoints can be easily run with
```bash
python ./src/services.py
```

> Note: flask is being used just for demonstration purposes. **DO NOT** use flask alone in a production environment.
> Visit [Flask deployment options](http://flask.pocoo.org/docs/1.0/deploying/).

## Authorization Helper

This class provides some utilities to handle token exchanged between the app and keycloak.

### Get the Token from the Get Token Client

In order to get the access token for the user 'testuser', one might use cUrl to perform a POST request:  

```bash
curl -v --data "grant_type=password&client_id=testGetTokenClient&username=testuser&password=user123" http://localhost:8080/auth/realms/testRealm/protocol/openid-connect/token
```
> * grant_type 'password' corresponds to the public access type for the client
> * client_id is the id of the client providing the access_token
> * username and password are the credentials for the user requesting the access token

The very same access token can be retrieved using (properly setup) *AuthorizationHelper.get_user_token()* (See [test.py](src/test.py) for having an example)

## Tests    
At the moment, a basic set of test cases are available.
They can be run with

```bash
python ./src/test.py
```