from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def get_ECPK_key_bytes(pk: EllipticCurvePrivateKey) -> bytes:
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def save_ECPK_key(pk: EllipticCurvePrivateKey, filename: str):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def load_ECPK_key(filename) -> EllipticCurvePrivateKey:
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None)

    return private_key


ecdsa_private_key = ec.generate_private_key(ec.SECP384R1())

save_ECPK_key(ecdsa_private_key, 'ecdsa_private_key.pem')

ecdsa_private_key_loaded = load_ECPK_key('ecdsa_private_key.pem')

print("Original Private Key", get_ECPK_key_bytes(ecdsa_private_key))
print("Loaded Private Key  ", get_ECPK_key_bytes(ecdsa_private_key_loaded))

try:
    assert ecdsa_private_key == ecdsa_private_key_loaded
    print("Private keys are equal")
except AssertionError:
    print("Private keys are not equal")
