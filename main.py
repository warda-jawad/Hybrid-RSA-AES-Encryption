from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from os import urandom
import hashlib

# Function to generate RSA keys (public and private)
def generate_rsa_keys(key):
    key = RSA.generate(key)  # Generate dynamic-bit RSA key pair
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Function to encrypt the AES key using RSA public key
def encrypt_aes_key(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return encrypted_aes_key

# Function to decrypt the AES key using RSA private key
def decrypt_aes_key(encrypted_aes_key, private_key):
    rsa_key = RSA.import_key(private_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    return aes_key

# S-box and inverse S-box
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)
inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
)


def sub_word(word: list[int]) -> bytes:
    substituted_word = bytes(s_box[i] for i in word)
    return substituted_word


def rcon(i: int) -> bytes:
    # From Wikipedia
    rcon_lookup = bytearray.fromhex("01020408102040801b36")
    rcon_value = bytes([rcon_lookup[i - 1], 0, 0, 0])
    return rcon_value


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for (x, y) in zip(a, b)])


def rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def key_expansion(key: bytes, numbercloumn: int = 4) -> list[list[list[int]]]:
    numberkey = len(key) // 4
    key_bit_length = len(key) * 8
    if key_bit_length == 128:
        numberround = 10
    elif key_bit_length == 192:
        numberround = 12
    else:  # 256-bit keys
        numberround = 14
    w = state_from_bytes(key)
    for i in range(numberkey, numbercloumn * (numberround + 1)):
        temp = w[i - 1]
        if i % numberkey == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), rcon(i // numberkey))
        elif numberkey > 6 and i % numberkey == 4:
            temp = sub_word(temp)
        w.append(xor_bytes(w[i - numberkey], temp))  # type: ignore

    return [w[i * 4 : (i + 1) * 4] for i in range(len(w) // 4)]


def add_round_key(state: list[list[int]], key_schedule: list[list[list[int]]], round: int):
    # XOR the state with the round key
    for r in range(4):
        for c in range(4):
            state[r][c] ^= key_schedule[round][r][c]


def sub_bytes(state: list[list[int]], box: list[int]):
    # Substitute bytes using the given S-box
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]


def shift_rows(state: list[list[int]]):
    # Shift rows of the state
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def inv_shift_rows(state: list[list[int]]):
    # Inverse of ShiftRows
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]


def galois_field_mul(a: int, b: int) -> int:
    # Perform Galois field multiplication
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        high_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit_set:
            a ^= 0x1B
        b >>= 1
    return p


def mix_column(column: list[int]):
    # Mix one column in MixColumns
    a = column[:]
    column[0] = galois_field_mul(a[0], 2) ^ galois_field_mul(a[1], 3) ^ a[2] ^ a[3]
    column[1] = a[0] ^ galois_field_mul(a[1], 2) ^ galois_field_mul(a[2], 3) ^ a[3]
    column[2] = a[0] ^ a[1] ^ galois_field_mul(a[2], 2) ^ galois_field_mul(a[3], 3)
    column[3] = galois_field_mul(a[0], 3) ^ a[1] ^ a[2] ^ galois_field_mul(a[3], 2)


def inv_mix_column(column: list[int]):
    # Inverse MixColumns transformation
    a = column[:]
    column[0] = galois_field_mul(a[0], 0x0E) ^ galois_field_mul(a[1], 0x0B) ^ galois_field_mul(a[2], 0x0D) ^ galois_field_mul(a[3], 0x09)
    column[1] = galois_field_mul(a[0], 0x09) ^ galois_field_mul(a[1], 0x0E) ^ galois_field_mul(a[2], 0x0B) ^ galois_field_mul(a[3], 0x0D)
    column[2] = galois_field_mul(a[0], 0x0D) ^ galois_field_mul(a[1], 0x09) ^ galois_field_mul(a[2], 0x0E) ^ galois_field_mul(a[3], 0x0B)
    column[3] = galois_field_mul(a[0], 0x0B) ^ galois_field_mul(a[1], 0x0D) ^ galois_field_mul(a[2], 0x09) ^ galois_field_mul(a[3], 0x0E)


def state_from_bytes(data: bytes) -> list[list[int]]:
    # Converts bytes to a 4x4 state matrix
    return [[data[r + c * 4] for c in range(4)] for r in range(4)]


def bytes_from_state(state: list[list[int]]) -> bytes:
    # Converts a 4x4 state matrix back to bytes
    return bytes(state[r][c] for c in range(4) for r in range(4))


def mix_columns(state: list[list[int]]):
    # Applies the MixColumns transformation
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mix_column(col)
        for r in range(4):
            state[r][c] = col[r]


def inv_mix_columns(state: list[list[int]]):
    # Applies the inverse of MixColumns
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        inv_mix_column(col)
        for r in range(4):
            state[r][c] = col[r]


def pkcs7_padding(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpadding(data: bytes) -> bytes:
    padding_length = data[-1]
    return data[:-padding_length]


def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_block(plaintext: bytes, key_schedule: list[list[list[int]]]) -> bytes:
    state = state_from_bytes(plaintext)
    add_round_key(state, key_schedule, 0)

    for round in range(1, len(key_schedule) - 1):
        sub_bytes(state, s_box)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)

    sub_bytes(state, s_box)
    shift_rows(state)
    add_round_key(state, key_schedule, len(key_schedule) - 1)

    return bytes_from_state(state)


def decrypt_block(ciphertext: bytes, key_schedule: list[list[list[int]]]) -> bytes:
    state = state_from_bytes(ciphertext)
    add_round_key(state, key_schedule, len(key_schedule) - 1)
    for round in range(len(key_schedule) - 2, 0, -1):
        inv_shift_rows(state)
        sub_bytes(state, inv_s_box)
        add_round_key(state, key_schedule, round)
        inv_mix_columns(state)
    inv_shift_rows(state)
    sub_bytes(state, inv_s_box)
    add_round_key(state, key_schedule, 0)
    return bytes_from_state(state)


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) % 16 != 0:
        raise ValueError("Plaintext must be a multiple of 16 bytes.")
    key_schedule = key_expansion(key)
    ciphertext = b"".join(
        encrypt_block(plaintext[i:i+16], key_schedule)
        for i in range(0, len(plaintext), 16)
    )
    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext must be a multiple of 16 bytes.")
    key_schedule = key_expansion(key)
    plaintext = b"".join(
        decrypt_block(ciphertext[i:i+16], key_schedule)
        for i in range(0, len(ciphertext), 16)
    )
    return plaintext


if __name__ == "__main__":

    print("RSA Encryption/Decryption")

    # Get user input for key size
    while True:
        try:
            key_size = int(input("Enter key size in bits (e.g., 2048, 3072, 4096): "))
            if key_size not in [2048, 3072, 4096]:
                raise ValueError
            break
        except ValueError:
            print("Invalid key size! Please enter 2048, 3072, or 4096.")

    while True:
        print("\nChoose an option:")
        print("1. Hipyird AES , RSA Encryption/Decryption")
        print("2. Exit")

        choice = input("Enter your choice (1-2): ")

        if choice == '1':
            # Encrypt a Message and Decrypt
            # Generate RSA keys
            private_key, public_key = generate_rsa_keys(key_size)
            key = urandom(16)  # Random 128-bit key
            hashed_data = hash_data(key)
            encrypted_aes_key = encrypt_aes_key(key, public_key)
            dynamic_plaintext = input("Enter a message to encrypt :  ")
            padded_data = pkcs7_padding(dynamic_plaintext.encode('utf-8'))
            print("Plaintext:", dynamic_plaintext)
            ciphertext = aes_encrypt(padded_data, key)
            print("Ciphertext:", ciphertext)
            # Decrypt AES key using RSA private key
            decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
            decrypted_padded_text = aes_decrypt(ciphertext, decrypted_aes_key)
            decrypted_text = pkcs7_unpadding(decrypted_padded_text)
            print("Decrypted Text:", decrypted_text)
            assert dynamic_plaintext == decrypted_text.decode('utf-8'), "Decryption failed!"

        elif choice == '2':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice, please try again.")

        input("Press Enter to continue...")
