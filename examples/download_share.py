import os
from src.oprf_ristretto25519_sha512 import OPRF
from pyseto import Key, Paseto
import pyseto
import json

sksm = '5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e'
file_key = "secret_file_key"

'''
Downloadshare
Alice wants to share a file with Bob
1. Step
- Alice creates a random access_key, auth_token, choose a secret password and calculates the oprf input
- Alice calculates the BlindedElement
- Alice sends the access_key, auth_token and BlindedElement to the server
'''
access_key = os.urandom(32)
auth_token = os.urandom(32)
password = "secretpassword"

oprf_input = access_key + password.encode('utf-8')
oprf_alice = OPRF(oprf_input)
blinded_element = oprf_alice.Blind()

# access_key, auth_token, blinded_element -> server

'''
2. Step
- Server creates a DonwloadUrl https://example.com/api/downloadurl/<access_key> and sends the url to bob via email
- Server stores the auth_token
- Server calculates the evaluatedElement and sends it to alice
'''

evaluated_element = OPRF.BlindEvaluate(bytes.fromhex(sksm), blinded_element)

# evaluated_element -> alice

'''
3. Step
- Alice calculate the output and use it a secret key (download_share_key)
- Alice encrypts the auth_token and the file_key using the download_share_key (here using Paseto). The Download File is encrypted with the file_key.
- Alice sends the password to Bob
- Alice sends the encrypted auth_token and the file_key to the server
'''
download_share_key = oprf_alice.Finalize(evaluated_element)

payload = {'auth_token': auth_token.hex(),
           'file_key': file_key}

paseto_key = Key.new(version=4, purpose="local", key=download_share_key)
paseto = Paseto.new(include_iat=True)  # Default values are exp=0(not specified) and including_iat=False
token = paseto.encode(
    paseto_key,
    payload=payload,
    serializer=json,
    implicit_assertion=access_key
    )

# password -> Bob
# token -> server

'''
4. Step
- Bob calculates the BlindedElement using the password and the access_key from the Download URL
'''

oprf_bob = OPRF(oprf_input)
blinded_element = oprf_bob.Blind()

# blinded_element -> Server

'''
5. Step
- Server calculates the evaluatedElement and sends it to Bob
- Server sends the encrypted auth_token and the file_key to the server
'''

evaluated_element = OPRF.BlindEvaluate(bytes.fromhex(sksm), blinded_element)

# evaluated_element, token -> Bob

'''
3. Step
- Bob calculates the output and use it a secret key (download_share_key)
- Bob decrypts the auth_token and the file_key using the download_share_key.
- Bob downloads the encrypted file where he authenticates to the server with the auth_token
- Bob decrypts the file with the file_key
'''

download_share_key = oprf_bob.Finalize(evaluated_element)

paseto_key = Key.new(version=4, purpose="local", key=download_share_key)
decoded = pyseto.decode(paseto_key, token, implicit_assertion=access_key, deserializer=json)

print(decoded.payload)
