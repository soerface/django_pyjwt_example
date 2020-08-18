#!/usr/bin/env python3

import sys
from datetime import datetime, timedelta

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Obviously, in a production setting, you would not have checked in the private key or the password in you repository
# Always keep your credentials save!
#
# Command for key generation:
# openssl genrsa -out private.pem -aes256 4096
# openssl rsa -pubout -in private.pem -out public.pem
with open('private.pem') as f:
    private_key_encrypted = f.read().encode()


private_key = load_pem_private_key(private_key_encrypted, password=b'asdf', backend=default_backend())

now = datetime.utcnow()
token = jwt.encode({
    'username': sys.argv[1] if len(sys.argv) > 1 else 'foobar',
    # expiration of the token. They should not live for an extended period of time since they can't be revoked
    'exp': now + timedelta(hours=1),
    # issued at
    'iat': now
}, private_key, algorithm='RS512')

# .decode() turns bytes into string, this is necessary to not get b'...' in the output
print(token.decode())
