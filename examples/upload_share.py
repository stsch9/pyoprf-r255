import os
from src.oprf_ristretto25519_sha512 import OPRF
from pyseto import Key, Paseto
import pyseto
import json

sksm = '5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e'
file_key = "secret_file_key"

'''
Uploadshare
Alice wants to send an Uploadshare to Bob
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
- Server creates a UploadUrl https://example.com/api/uploadurl/<access_key> and sends the url to bob via email
- Server stores the auth_token
- Server calculates the evaluatedElement and sends it to Alice
'''

evaluated_element = OPRF.BlindEvaluate(bytes.fromhex(sksm), blinded_element)

# evaluated_element -> alice

'''
3. Step
- Alice calculates the output and uses it as secret key (upload_share_key)
- Alice encrypts the auth_token and the file_key using the upload_share_key (here using Paseto v4, committing AEAD). The Upload File will be encrypted with the file_key.
- Alice sends the password to Bob
- Alice sends the encrypted auth_token, file_key and upload_url to the server
'''
upload_share_key = oprf_alice.Finalize(evaluated_element)

payload = {'upload_url': 'https://example.com/api/uploadurl/' + access_key.hex(),
           'auth_token': auth_token.hex(),
           'file_key': file_key}

paseto_key = Key.new(version=4, purpose="local", key=upload_share_key)
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
- Bob calculates the BlindedElement using the password and the access_key from the Upload URL
'''

oprf_bob = OPRF(oprf_input)
blinded_element = oprf_bob.Blind()

# blinded_element -> Server

'''
5. Step
- Server calculates the evaluatedElement and sends it to Bob
- Server sends the encrypted auth_token, file_key, and upload_url to Bob
'''

evaluated_element = OPRF.BlindEvaluate(bytes.fromhex(sksm), blinded_element)

# evaluated_element, token -> Bob

'''
3. Step
- Bob calculates the output and use it a secret key (upload_share_key)
- Bob decrypts the auth_token, file_key and the upload_url using the upload_share_key.
- Bob compares the upload url he received by e-mail with the upload_url he just decrypted
- Bob encrypts the file with the file_key
- Bob uploads the encrypted file where he authenticates to the server with the auth_token
'''

upload_share_key = oprf_bob.Finalize(evaluated_element)

paseto_key = Key.new(version=4, purpose="local", key=upload_share_key)
decoded = pyseto.decode(paseto_key, token, implicit_assertion=access_key, deserializer=json)

print(decoded.payload)
