

# AES Encryption Tool

A **GUI-based AES (Advanced Encryption Standard) Encryption and Decryption Tool** built in Python. This tool allows users to encrypt and decrypt text using AES in **ECB (Electronic Codebook)** or **CBC (Cipher Block Chaining)** mode, with customizable key sizes and output formats.


## Features

* **User-Friendly GUI** built with **Tkinter**.
* Supports **AES key sizes**: 128-bit, 192-bit, 256-bit.
* Supports **encryption modes**: ECB and CBC.
* Allows **custom keys** (Base64 encoded) or generates **secure random keys**.
* Automatically generates **Initialization Vector (IV)** for CBC mode.
* Supports **output formats**: Base64 and Hexadecimal.
* **Encrypt / Decrypt** text with a single click.
* Status messages to indicate success or failure.


## Libraries Used

* **Tkinter** – GUI development.
* **PyCryptodome** (`Crypto.Cipher`, `Crypto.Util.Padding`, `Crypto.Random`) – AES encryption/decryption, padding, and key/IV generation.
* **Base64** – Encode/decode binary ciphertext for text display.
* **Binascii** – Convert binary ciphertext to Hexadecimal.
  

## Installation

1. **Clone the repository**:

```bash
git clone <your-repo-url>
```

2. **Install required libraries**:

```bash
pip install pycryptodome
```

## Usage

1. Run the Python script:

```bash
python aes_gui.py
```

2. Enter the **text** you want to encrypt or decrypt.
3. Provide or generate a **secret key**.
4. If using CBC mode, provide or generate an **IV (Initialization Vector)**.
5. Select **AES mode** (ECB/CBC) and **output format** (Base64/Hex).
6. Click **Encrypt** or **Decrypt** to see results.
7. Use **Clear All** to reset fields.


## How It Works

* **AES (Advanced Encryption Standard)** is a **symmetric key encryption algorithm**, meaning the same key is used for encryption and decryption.
* **ECB (Electronic Codebook)**: Simple block-by-block encryption. Not recommended for sensitive data.
* **CBC (Cipher Block Chaining)**: Each block depends on the previous block; more secure. Requires IV.
* **Padding**: Ensures plaintext matches AES block size (16 bytes). Removed after decryption.
* **Output Formats**: Base64 (text-friendly) or Hexadecimal (hex display).

