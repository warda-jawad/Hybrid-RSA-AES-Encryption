# Hybrid-RSA-AES-Encryption
**Enhanced Hybrid RSA-AES Encryption with PKCS and SHA-256**

In this project, I implemented a hybrid encryption scheme that combines RSA and AES for enhanced security:

## Encryption Components
- **RSA Encryption**: Used to securely encrypt the AES key.
- **AES Encryption**: Responsible for encrypting the actual data.

## Security Enhancements
- **PKCS1_OAEP Padding**: Integrated to ensure secure padding for RSA encryption, offering better protection against cryptographic attacks.
- **PKCS7 Padding and Unpadding**: Applied to AES encryption to ensure data is properly padded to match the block size.
- **SHA-256 Hashing**: Integrated a hashing function using SHA-256 to hash data before encryption, adding an extra layer of security.

These enhancements strengthen the encryption system, ensuring secure and reliable data transmission.
