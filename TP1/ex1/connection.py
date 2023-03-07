import asyncio

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from TP1.ex1.encryption import get_ECDSA_keys_receiver, get_ECDH_keys, get_public_bytes, \
    get_ECDSA_EMITTER_public_key

RECEIVER_HOST = "127.0.0.1"
RECEIVER_PORT = 9000


async def start_server(host: str, port: int, handler):
    server = await asyncio.start_server(handler, host, port)

    return server


async def initialize_session_receiver(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    print("Connection from:", writer.get_extra_info("peername"))

    ecdsa_private_key, ecdsa_public_key = await get_ECDSA_keys_receiver()
    ecdh_private_key, ecdh_public_key = await get_ECDH_keys()

    print("ECDSA private key:", ecdsa_private_key.private_bytes(Encoding.PEM, format=PrivateFormat.PKCS8,
                                                                encryption_algorithm=NoEncryption()))
    print("ECDSA public key:", ecdsa_public_key.public_bytes(Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))

    # Receive emitter's ECDH public key
    signature = await reader.read(1000)
    emitter_public_key_bytes = await reader.read(1000)
    print("Emitter's public key received.")

    try:
        emitter_ECDSA_public_key = await get_ECDSA_EMITTER_public_key()

        emitter_ECDSA_public_key.verify(signature, emitter_public_key_bytes, ec.ECDSA(hashes.SHA256()))
        print("Emitter's signature verified.")
    except InvalidSignature:
        print("Emitter's signature verification failed.")
        raise Exception("Man in the middle attack detected!")

    # Sign ECDH public key with ECDSA private key
    signature = ecdsa_private_key.sign(
        await get_public_bytes(ecdh_private_key),
        ec.ECDSA(hashes.SHA256())
    )
    print("Signature:", signature)
    print("Signature length:", len(signature))
    print("ECDH public key:", await get_public_bytes(ecdh_private_key))

    # Send ECDH public key with signature to the emitter
    writer.write(signature)
    await writer.drain()

    writer.write(await get_public_bytes(ecdh_private_key))
    await writer.drain()
    print("Receiver's public key sent.")

    # Load emitter's public key
    emitter_public_key = load_pem_public_key(emitter_public_key_bytes)

    # Generate shared secret from ECDH key exchange
    shared_key = ecdh_private_key.exchange(ec.ECDH(), emitter_public_key)
    print("Shared secret derived.")

    # Derive cipher and MAC keys from shared secret using HKDF
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'secret')
    hkdf_output = hkdf.derive(shared_key)
    print("HKDF output derived.")

    # Split HKDF output into cipher and MAC keys
    cipher_key = hkdf_output[:32]
    mac_key = hkdf_output[32:]

    return cipher_key, mac_key
