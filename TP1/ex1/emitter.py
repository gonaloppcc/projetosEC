import asyncio

from TP1.ex1.connection import initialize_session_emitter, get_connection
from TP1.ex1.encryption import generate_random_nonce, authenticate_and_encrypt_message
from receiver import RECEIVER_HOST, RECEIVER_PORT

READER_BUFFER_SIZE = 1024




async def main():
    reader, writer = await get_connection(RECEIVER_HOST, RECEIVER_PORT)

    while True:
        message = input("Message: ")
        message_bytes = message.encode("utf-8")

        if message in ["q", "quit", "exit"]:
            writer.close()
            break

        cipher_key, mac_key = await initialize_session_emitter(reader, writer)
        print("PRIVATE INFORMATION", "\n\tCipher Key:", cipher_key, "\n\tMAC Key:", mac_key)

        nonce = generate_random_nonce()

        # print("Nonce:", nonce[:10], '...', nonce[-10:])
        print("Nonce:", nonce)

        writer.write(nonce)
        await writer.drain()
        print("Nonce sent.")

        ciphertext, tag, _nonce = authenticate_and_encrypt_message(message_bytes, cipher_key, mac_key, nonce)

        # Send encrypted message and authentication tag to the receiver
        writer.write(tag)
        writer.write(ciphertext)

        print('Tag:', tag[:10], '...', tag[-10:])
        print('Ciphertext:', ciphertext[:10], '...', ciphertext[-10:])
        print("\tTag and ciphertext sent.")

        ack = await reader.read(READER_BUFFER_SIZE)
        assert ack == b"ACK"


if __name__ == "__main__":
    try:
        asyncio.run(main())
        print("Done.")
    except KeyboardInterrupt:
        print("Exiting...")
    except ConnectionRefusedError:
        print("Connection Refused. Is the receiver running?")
    except ConnectionResetError:
        print("Connection Reset. Is the receiver running?")
    except Exception as e:
        print("Something went wrong:", e)
