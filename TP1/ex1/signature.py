from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Generate a private key
private_key = ec.generate_private_key(ec.SECP384R1())

# Get the corresponding public key
public_key = private_key.public_key()

# A message to be signed
message = b"Hello, world!"

# Sign the message with the private key
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# Verify the signature using the public key
try:
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print("Signature is valid")
except:
    print("Signature is invalid")
