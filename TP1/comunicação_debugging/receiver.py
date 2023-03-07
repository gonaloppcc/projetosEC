import asyncio

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key

READER_BUFFER_SIZE = 1024

RECEIVER_HOST = "127.0.0.1"
RECEIVER_PORT = 9000


async def start_server(host: str, port: int, handler):
    server = await asyncio.start_server(handler, host, port)

    return server


def unpad_message(message: bytes) -> bytes:
    """Unpad message with PKCS7 padding"""
    print("Padded message:", message)
    unpadder = padding.PKCS7(128).unpadder()

    data = unpadder.update(message)

    return data + unpadder.finalize()


def decrypt_message(ciphertext: bytes, key: bytes, nonce: bytes):
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


async def initialize_session(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    print("Connection from:", writer.get_extra_info("peername"))

    # Generate ECDSA key pair
    ecdsa_private_key = ec.generate_private_key(ec.SECP384R1())
    ecdsa_public_key = ecdsa_private_key.public_key() # TODO: This should be a constant known

    ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
    ecdh_public_key = ecdh_private_key.public_key()

    print("ECDH public key:",
          ecdh_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    # Receive emitter's ECDH public key
    emitter_public_key_bytes = await reader.read(1000)

    print('[RECEIVED] Emitter public key:', emitter_public_key_bytes[:50], "...")
    print("Emitter's public key received.")

    # Send ECDH public key to the emitter
    writer.write(ecdh_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    await writer.drain()

    print("Receiver's public key sent.")

    print('[SENT] ECDH public key:',
          ecdh_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)[:50], "...")

    # Load emitter's public key
    emitter_public_key = load_pem_public_key(emitter_public_key_bytes)

    # Generate shared secret from ECDH key exchange
    shared_key = ecdh_private_key.exchange(ec.ECDH(), emitter_public_key)

    print("Shared Secret Derived:", shared_key[:2], "...", shared_key[-2:])
    print("Shared secret derived.")

    # Derive cipher and MAC keys from shared secret using HKDF
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'secret')
    hkdf_output = hkdf.derive(shared_key)

    print("HKDF output:", hkdf_output[:2], "...", hkdf_output[-2:])
    print("HKDF output derived.")

    # Split HKDF output into cipher and MAC keys
    cipher_key = hkdf_output[:32]
    mac_key = hkdf_output[32:]

    print("Cipher key:", cipher_key[:2], "...", cipher_key[-2:])
    print("MAC key:", mac_key[:2], "...", mac_key[-2:])

    return cipher_key, mac_key


async def connection_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    cipher_key, mac_key = await initialize_session(reader, writer)

    print("PRIVATE INFORMATION\n", "Cipher Key:", cipher_key, "\nMAC Key:", mac_key)

    # Receive nonce from the emitter
    nonce = await reader.read(16)

    # print("[RECEIVED] Nonce:", nonce[:2], "...", nonce[-2:])
    print("Nonce received")

    tag = await reader.read(32)
    ciphertext = await reader.read(1000)

    print('[RECEIVED] Tag:', tag[:2], '...', tag[-2:])
    print('[RECEIVED] Ciphertext:', ciphertext[:2], '...', ciphertext[-2:])
    print("ciphertext length:", len(ciphertext))
    print("Tag and ciphertext received.")

    # Authenticate message with HMAC-SHA256
    try:
        verify_message(ciphertext, key=mac_key, nonce=nonce, tag=tag)
        # print('[RECEIVED] Message authenticated successfully')
        print("Message authenticated successfully.")
    except InvalidSignature:
        # print('[RECEIVED] !!! Message authentication FAILED !!!')
        print("!!! MESSAGE AUTHENTICATION FAILED !!!")

    # Decrypt message with AES-256 in CBC mode
    plaintext = decrypt_message(ciphertext, cipher_key, nonce)
    # print('[RECEIVED] Decrypted message:', plaintext)
    print("Plaintext received: ", plaintext)


async def main():
    server = await asyncio.start_server(connection_handler, RECEIVER_HOST, RECEIVER_PORT)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Serving on {addrs}')

    async with server:
        await server.serve_forever()
        server.close()


# Test Code
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except ConnectionResetError:
        print("Connection closed")

    except KeyboardInterrupt:
        print("Receiver closed...")

    except Exception as e:
        print("Something went wrong: ", e)
