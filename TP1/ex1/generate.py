from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ecdsa_private_key = ec.generate_private_key(ec.SECP384R1())
ecdsa_public_key = ecdsa_private_key.public_key()

private_key_bytes = ecdsa_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_bytes = ecdsa_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('private_key.pem', 'wb') as pem_out:
    pem_out.write(private_key_bytes)

with open('public_key.pem', 'wb') as pem_out:
    pem_out.write(public_key_bytes)

with open('private_key.pem', 'rb') as pem_in:
    private_key_bytes = pem_in.read()

private_key_loaded = serialization.load_pem_private_key(
    private_key_bytes,
    password=None
)

private_key_loaded_bytes = private_key_loaded.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

print("Original Private Key", private_key_bytes)
print("Loaded Private Key  ", private_key_loaded_bytes)

try:
    assert private_key_bytes == private_key_loaded_bytes
    print("Private keys are equal")
except AssertionError:
    print("Private keys are not equal")

with open('public_key.pem', 'rb') as pem_in:
    public_key_bytes = pem_in.read()

public_key_loaded = serialization.load_pem_public_key(
    public_key_bytes
)

public_key_loaded_bytes = public_key_loaded.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Original Public Key", public_key_bytes)
print("Loaded Public Key  ", public_key_loaded_bytes)

try:
    assert public_key_bytes == public_key_loaded_bytes
    print("Public keys are equal")
except AssertionError:
    print("Public keys are not equal")
