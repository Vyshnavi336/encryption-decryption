from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Function to encrypt a message
def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_bytes).decode()

# Function to decrypt a message
def decrypt(encrypted_text, key):
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    return decrypted_bytes.decode()

# Taking user input
message = input("Enter the message: ")
password = input("Enter the encryption key (16/24/32 bytes): ").encode()
print(len(password))
if len(password) not in [16, 24, 32]:
    raise ValueError("Key must be 16, 24, or 32 bytes long.")

# Encrypting the message
encrypted_msg = encrypt(message, password)
print(f"Encrypted Message: {encrypted_msg}")

# Decrypting the message
decrypted_msg = decrypt(encrypted_msg, password)
print(f"Decrypted Message: {decrypted_msg}")