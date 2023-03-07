import asyncio
import os
import time

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from receiver import RECEIVER_HOST, RECEIVER_PORT

READER_BUFFER_SIZE = 1024


async def get_connection(host: str, port: int) -> (asyncio.StreamReader, asyncio.StreamWriter):
    connection = await asyncio.open_connection(host, port)

    return connection


NONCE_HASH_FUNCTION = hashes.SHAKE128
NONCE_HASH_SIZE = 16
DIGEST_SIZE = 128


def generate_random_nonce():
    """ Generate random nonce using XOF hash function """
    xof = hashes.Hash(NONCE_HASH_FUNCTION(DIGEST_SIZE))
    xof.update(os.urandom(NONCE_HASH_SIZE))

    return xof.finalize()[0:NONCE_HASH_SIZE]


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


def authenticate_and_encrypt_message(message: bytes, cipher_key: bytes, mac_key: bytes, nonce: bytes) -> (
        bytes, bytes, bytes):
    """Encrypt message with AES-256 in OFB mode and authenticate with HMAC-SHA256"""

    ciphertext = encrypt_message(message, cipher_key, nonce)

    tag = authenticate_message(ciphertext, mac_key, nonce)

    return ciphertext, tag, nonce


async def main():
    reader, writer = await get_connection(RECEIVER_HOST, RECEIVER_PORT)

    # Generate ECDH (Elliptic-curve Diffie–Hellman) key pair
    ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
    ecdh_public_key = ecdh_private_key.public_key()

    # print("ECDH public key:", ecdh_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    # Send ECDH public key to the receiver
    writer.write(ecdh_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    await writer.drain()

    print("Emitter's public key sent.")

    # Receive receiver's ECDH public key
    receiver_public_key_bytes = await reader.read(1000)

    print("Receiver's public key received.")

    # Load receiver's public key
    receiver_public_key = load_pem_public_key(receiver_public_key_bytes)

    # print("ECDH public key loaded:",
    #      receiver_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)[:50], "...")

    # Generate shared secret from ECDH key exchange
    shared_secret = ecdh_private_key.exchange(ec.ECDH(), receiver_public_key)

    # print("Shared Secret Derived:", shared_secret[:50], "...")
    print("Shared secret derived.")

    # Derive cipher and MAC keys from shared secret using HKDF
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'secret')
    hkdf_output = hkdf.derive(shared_secret)
    cipher_key, mac_key = hkdf_output[:32], hkdf_output[32:]

    print("PRIVATE INFORMATION")
    print("Cipher Key:", cipher_key)
    print("MAC Key:", mac_key)

    while True:
        # message = input("Message: ").encode("utf-8")

        # TODO: Uncomment this section

        message = "olaaaaaaaaaaaaaaaaaaaaaaa".encode("utf-8")

        if message in ["q", "quit", "exit"]:
            writer.close()
            break

        nonce = generate_random_nonce()

        print("Nonce generated:", nonce)
        print("Nonce generated.")

        writer.write(nonce)
        await writer.drain()
        print("Nonce sent.")

        # ciphertext, tag, _nonce = authenticate_and_encrypt_message(message, cipher_key, mac_key, nonce)
        tag = b'x' * 32
        ciphertext = b'x' * 16

        # Send encrypted message and authentication tag to the receiver
        writer.write(tag)
        writer.write(ciphertext)
        await writer.drain()

        # print("Tag:", tag[:2], "...", tag[-2:])
        # print("Ciphertext:", ciphertext[:2], "...", ciphertext[-2:])
        # print("ciphertext length:", len(ciphertext))
        # print("Tag and ciphertext sent.")

        time.sleep(2)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")
    except ConnectionRefusedError:
        print("Connection Refused. Is the receiver running?")
    except ConnectionResetError:
        print("Connection Reset. Is the receiver running?")
    except Exception as e:
        print("Something went wrong:", e.with_traceback())
