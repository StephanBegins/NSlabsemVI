from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


# Function to encrypt plaintext
def encrypt_message(key, plaintext):
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Create a cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create an encryptor object
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext  # Return IV + ciphertext


# Function to decrypt ciphertext
def decrypt_message(key, ciphertext):
    # Extract the IV from the ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Create a cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create a decryptor object
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode()


# Example usage
if __name__ == "__main__":
    # 32-byte key for AES-256
    key = os.urandom(32)

    # Plaintext message
    plaintext = "This is message by stephan."

    # Encrypt the message
    encrypted = encrypt_message(key, plaintext)
    print("Encrypted message:", encrypted)

    # Decrypt the message
    decrypted = decrypt_message(key, encrypted)
    print("Decrypted message:", decrypted)
