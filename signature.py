from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import Crypto
import sys

message = 'signature'
digest = SHA256.new()
digest.update(message.encode('utf-8'))

i = sys.argv[1]
f = open("../databases/p1/privrecipients"+i, "r")
pk=f.read()
f2 = open("../databases/p1/pubrecipients"+i, "r")
pk2=f2.read()

private_key=RSA.import_key(pk)
signer = PKCS1_v1_5.new(private_key)
sig = signer.sign(digest)
print(sig)
print(pk2)
