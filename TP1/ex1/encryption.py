import os

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

RECEIVER_ECDSA_PRIVATE_KEY = b'-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDBkAJ//1EY5QDLLkTo\nK1Fw2u72syJr1PezOXJIZ5sbgldU+3ek7c36QlcpS1ivIJyhZANiAATy1f2kEnja\nurTOJS/DcriE08pMws4Q6EMeb38Djoh0NkWJGPBc8aSnv4Os6dk8kCaX2VvQnrdK\nWP67FqOvT9l1PzSgXQIqsDrhd5eDAkrhMt6ozSDtw22ulOqi3KeggMQ=\n-----END PRIVATE KEY-----\n'
RECEIVER_ECDSA_PUBLIC_KEY = b'-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8tX9pBJ42rq0ziUvw3K4hNPKTMLOEOhD\nHm9/A46IdDZFiRjwXPGkp7+DrOnZPJAml9lb0J63Slj+uxajr0/ZdT80oF0CKrA6\n4XeXgwJK4TLeqM0g7cNtrpTqotynoIDE\n-----END PUBLIC KEY-----\n'

EMITTER_ECDSA_PRIVATE_KEY = b'-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCafePBefGG4bXt0vm7\necsH9D4rJblSUH9DMRh21oUbns+3GMRRyj/ykQ8kZC94GUShZANiAAQTJpqMsWcz\n1c+wZ6IHdF2kJsm6AU9TOvYsZTjdIgrcV+6mw0yYBrC/6X9RbnFRNvUuLWEDGoqU\ngY7IplCZ5cHyVYajfcuPw4Y1etwtGe9dBlLog+I10XbezCAfOdSZXIk=\n-----END PRIVATE KEY-----\n'
EMITTER_ECDSA_PUBLIC_KEY = b'-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEEyaajLFnM9XPsGeiB3RdpCbJugFPUzr2\nLGU43SIK3FfupsNMmAawv+l/UW5xUTb1Li1hAxqKlIGOyKZQmeXB8lWGo33Lj8OG\nNXrcLRnvXQZS6IPiNdF23swgHznUmVyJ\n-----END PUBLIC KEY-----\n'

NONCE_HASH_FUNCTION = hashes.SHAKE128
NONCE_HASH_SIZE = 16
DIGEST_SIZE = 128


def unpad_message(message: bytes) -> bytes:
    """Unpad message with PKCS7 padding"""
    unpadder = padding.PKCS7(128).unpadder()

    data = unpadder.update(message)

    return data + unpadder.finalize()


def decrypt_message(ciphertext: bytes, key: bytes, nonce: bytes):
    print("\t\tnonce:", nonce)
    cipher = Cipher(algorithms.AES256(key), modes.OFB(nonce[:16]))
    decryptor = cipher.decryptor()
    unpadded_message = decryptor.update(ciphertext) + decryptor.finalize()

    message = unpad_message(unpadded_message)

    return message


def verify_message(message: bytes, key: bytes, nonce: bytes, tag: bytes) -> bool:
    hmac_algorithm = hmac.HMAC(key, hashes.SHA256())
    hmac_algorithm.update(nonce + message)

    hmac_algorithm.verify(tag)

    return True


async def get_public_bytes(ecdh_private_key):
    return ecdh_private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


async def get_ECDSA_keys_receiver():
    private_key_bytes = RECEIVER_ECDSA_PRIVATE_KEY
    public_key_bytes = RECEIVER_ECDSA_PUBLIC_KEY

    ecdsa_private_key = load_pem_private_key(private_key_bytes, password=None)
    ecdsa_public_key = load_pem_public_key(public_key_bytes)

    return ecdsa_private_key, ecdsa_public_key


async def get_ECDSA_keys_emitter():
    private_key_bytes = EMITTER_ECDSA_PRIVATE_KEY
    public_key_bytes = EMITTER_ECDSA_PUBLIC_KEY

    ecdsa_private_key = load_pem_private_key(private_key_bytes, password=None)
    ecdsa_public_key = load_pem_public_key(public_key_bytes)

    return ecdsa_private_key, ecdsa_public_key


async def get_ECDSA_EMITTER_public_key():
    return load_pem_public_key(EMITTER_ECDSA_PUBLIC_KEY)


async def get_ECDSA_RECEIVER_public_key():
    return load_pem_public_key(RECEIVER_ECDSA_PUBLIC_KEY)


async def get_ECDH_keys():
    ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
    ecdh_public_key = ecdh_private_key.public_key()

    return ecdh_private_key, ecdh_public_key


def generate_random_nonce():
    """ Generate random nonce using XOF hash function """
    xof = hashes.Hash(NONCE_HASH_FUNCTION(DIGEST_SIZE))
    xof.update(os.urandom(NONCE_HASH_SIZE))

    return xof.finalize()[0:NONCE_HASH_SIZE]


def authenticate_and_encrypt_message(message: bytes, cipher_key: bytes, mac_key: bytes, nonce: bytes) -> (
        bytes, bytes, bytes):
    """Encrypt message with AES-256 in OFB mode and authenticate with HMAC-SHA256"""

    ciphertext = encrypt_message(message, cipher_key, nonce)

    tag = authenticate_message(ciphertext, mac_key, nonce)

    return ciphertext, tag, nonce


def pad_message(message: bytes) -> bytes:
    """Pad message with PKCS7 padding"""
    padder = padding.PKCS7(128).padder()

    padded_data = padder.update(message)

    return padded_data + padder.finalize()


def encrypt_message(message: bytes, key: bytes, nonce: bytes):
    padded_message = pad_message(message)
    print("Padded message:", padded_message)

    cipher = Cipher(algorithms.AES256(key), modes.OFB(nonce[:16]))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return ciphertext


def authenticate_message(message: bytes, key: bytes, nonce: bytes) -> bytes:
    hmac_algorithm = hmac.HMAC(key, hashes.SHA256())
    hmac_algorithm.update(nonce + message)

    tag = hmac_algorithm.finalize()

    return tag
