import asyncio

from cryptography.exceptions import InvalidSignature

from TP1.ex1.connection import RECEIVER_HOST, RECEIVER_PORT, initialize_session_receiver
from TP1.ex1.encryption import verify_message, decrypt_message

READER_BUFFER_SIZE = 1024


async def connection_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    while True:
        print("-" * 40, "CONNECTION INFO", "-" * 40)
        try:
            cipher_key, mac_key = await initialize_session_receiver(reader, writer)
        except ValueError:
            print("Emitter closed connection.")
            break

        print("-" * 40, "PRIVATE INFORMATION", "-" * 40, "\nCipher Key:", cipher_key, "\nMAC Key:", mac_key)

        # Receive nonce from the emitter
        print("-" * 40, "MESSAGE INFO", "-" * 40)
        nonce = await reader.read(16)
        print("Nonce:", nonce[:10], '...', nonce[-10:])

        tag = await reader.read(32)
        ciphertext = await reader.read(1000)

        print('Tag:', tag[:10], '...', tag[-10:])
        print('Ciphertext:', ciphertext[:10], '...', ciphertext[-10:])
        print("Tag and ciphertext received.")
        print("-" * 80)

        # Authenticate message with HMAC-SHA256
        try:
            verify_message(ciphertext, key=mac_key, nonce=nonce, tag=tag)
            print("Message authenticated successfully.")
        except InvalidSignature:
            print("!!! MESSAGE AUTHENTICATION FAILED !!!")

        # Decrypt message with AES-256 in CBC mode
        plaintext = decrypt_message(ciphertext, cipher_key, nonce)
        utf8_plaintext = plaintext.decode("utf-8")
        print(f"Plaintext received: \"{utf8_plaintext}\"")

        # Send ACK to emitter
        writer.write(b'ACK')


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
