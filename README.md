# Symantec Removable Media Encryption Tool

A lightweight Python implementation for reading, decrypting, inspecting, and experimentally creating encrypted files compatible with the file format used by **Symantec Endpoint Encryption Removable Media Encryption / Removable Media Access Utility**.

The project was developed through independent file-format analysis and interoperability testing.

Its primary purpose is to allow recovery and processing of existing Symantec-encrypted removable-media files on systems where the original Windows utility is unavailable or impractical to use.

## Features

- Decrypt existing Symantec Removable Media encrypted files
- Password-based key recovery
- Recursive directory processing
- Optional removal of encrypted `.XML` files after successful recovery
- Inspection of container metadata without a password
- Experimental creation of new encrypted containers
- Automatic encryption self-test
- Linux-friendly command-line interface
- No dependency on the original Symantec software

## Status

### Decryption

Decryption support is considered stable for the tested password-protected containers.

The implementation has successfully recovered both text and binary files, including large PDF files.

The resulting plaintext was verified byte-for-byte where reference data was available.

### Payload encryption

The payload encryption algorithm has been independently verified against existing Symantec containers.

A Symantec-generated encrypted file was:

1. decrypted;
2. encrypted again using the recovered original DEK;
3. reconstructed without modifying its original header;
4. compared against the original encrypted container.

The reconstructed files were **identical byte-for-byte**, including on a multi-megabyte PDF.

This confirms the AES payload encryption and per-chunk IV generation implemented by this project.

### New container creation

Creation of entirely new password-protected containers is currently considered **experimental**.

The generated format follows the structure reconstructed from existing Symantec files and can be decrypted by this implementation.

However, containers generated from scratch have not yet been tested directly with the original Symantec Removable Media Access Utility.

Therefore:

> Reading existing tested Symantec containers is supported. Writing new containers is experimental until compatibility with the original Symantec utility has been independently confirmed.

## Requirements

- Python 3.9 or newer
- `cryptography`

Install the dependency with:

```bash
python3 -m pip install cryptography
```

## Usage

The tool provides three commands:

```text
encrypt
decrypt
info
```

### Decrypt a file

```bash
python3 rmau.py decrypt document.pdf.XML
```

The password is requested interactively.

The output is written as:

```text
document.pdf
```

### Password file

The password can instead be read from a file:

```bash
python3 rmau.py decrypt -p password.txt document.pdf.XML
```

The password file should contain the password as UTF-8 text.

Trailing CR/LF characters are ignored.

### Decrypt a directory

```bash
python3 rmau.py decrypt -p password.txt /path/to/files
```

This processes encrypted `.XML` files in the specified directory.

For recursive processing:

```bash
python3 rmau.py decrypt -p password.txt -r /path/to/files
```

### Clean recovery

After verifying that recovery works correctly, encrypted `.XML` files can automatically be removed after successful decryption:

```bash
python3 rmau.py decrypt -p password.txt -r --delete /path/to/files
```

The encrypted source is removed **only after the plaintext has been successfully written**.

It is strongly recommended to perform the first recovery without `--delete`.

### Existing destination files

By default, an existing plaintext destination is not overwritten.

Use:

```bash
python3 rmau.py decrypt -p password.txt --force document.pdf.XML
```

to allow replacement.

## Inspect a container

Container information can be displayed without decrypting the file:

```bash
python3 rmau.py info document.pdf.XML
```

Example information includes:

```text
File       : document.pdf.XML
Originale  : document.pdf
Header     : 2430 byte
Alignment  : 512
Data       : 0xa00
Ciphertext : 1991792 byte
Padding    : 14
SHA-256 DEK: ...
```

No password is required for this operation because these values are stored in the clear-text container header.

## Encryption

A new password-protected container can be created with:

```bash
python3 rmau.py encrypt -p password.txt document.pdf
```

The resulting file is:

```text
document.pdf.XML
```

A new random Data Encryption Key is generated for every file.

The original plaintext is not modified.

### Recursive encryption

An entire directory can be processed with:

```bash
python3 rmau.py encrypt -p password.txt -r /path/to/files
```

Existing `.XML` containers are excluded from recursive encryption.

### Encryption self-test

Before writing a newly encrypted container, the program performs an internal round-trip test:

```text
plaintext
    |
    v
 encrypt
    |
    v
ciphertext
    |
    v
 decrypt
    |
    v
recovered plaintext
    |
    v
byte-for-byte comparison
```

The encrypted file is accepted only if the recovered plaintext exactly matches the input.

This verifies the cryptographic transformation but does **not**, by itself, prove that a newly generated container will be accepted by every version of the original Symantec utility.

## File format

The encrypted files use `.XML` as an additional extension, for example:

```text
report.pdf
report.pdf.XML
```

Despite the extension, the file is not simply an XML document.

It consists conceptually of:

```text
+--------------------------------+
| UTF-16LE XML header             |
+--------------------------------+
| alignment / metadata area       |
+--------------------------------+
| encrypted file data             |
|                                 |
| AES-CBC chunks                  |
+--------------------------------+
```

The XML header contains information including:

- original filename;
- creation information;
- alignment length;
- key verification hash;
- password-wrapped encryption key.

Containers examined during development used an alignment length of:

```text
512 bytes
```

## Password key derivation

For the tested password-protected containers, the password is encoded as UTF-16LE and hashed with SHA-256:

```text
KEK = SHA256(password encoded as UTF-16LE)
```

This produces a 256-bit Key Encryption Key.

The password-wrapped key stored in the XML header is then decrypted using AES-256 ECB:

```text
DEK = AES-256-ECB-DECRYPT(wrappedkey, KEK)
```

The recovered DEK is 128 bits.

Its validity is checked against the SHA-256 hash stored in the container:

```text
SHA256(DEK) == header hash
```

A mismatch indicates an incorrect password or unsupported/corrupt container.

## File encryption

The actual file contents are encrypted using:

```text
AES-128-CBC
```

with the recovered 128-bit DEK.

The payload is processed independently in chunks corresponding to the container's `AlignmentLength`.

For the tested files:

```text
AlignmentLength = 512
```

Each chunk uses a deterministic IV derived from its chunk number.

The IV is not stored before every encrypted chunk.

This detail is important: treating the first 16 bytes of each 512-byte region as a stored IV corrupts the recovered file.

## Chunk IV generation

The IV generation reconstructed from the format is equivalent to:

```python
def chunk_iv(n):
    words = []

    for _ in range(4):
        n = (0x3039 - (n * 0x3E39B193 & 0xffffffff)) & 0x7fffffff
        words.append(n)

    return struct.pack("<4I", *words)
```

Four 32-bit little-endian values form the 16-byte AES-CBC IV.

The chunk index starts at zero.

This algorithm has been validated by decrypting existing Symantec files and by reproducing their encrypted payload byte-for-byte.

## Padding

The plaintext uses zero padding to reach an AES block boundary.

The number of padding bytes is stored in the container metadata immediately before the encrypted payload.

After decryption, that number of bytes is removed from the end of the plaintext.

The observed padding range is therefore:

```text
0..15 bytes
```

## Container layout

The XML header contains a comment of the form:

```xml
<!--GETRSFileHeaderSize=0x000008E0-->
```

This provides the header size.

The beginning of encrypted data is obtained by aligning the end of the header to the container's `AlignmentLength`.

Conceptually:

```text
data_offset = align_up(header_size, AlignmentLength)
```

The padding count is stored immediately before this offset.

## Wrapped keys

Original Symantec containers may contain multiple key recovery mechanisms, including elements such as:

```text
Password
Certificate
UPC
```

These appear to represent independent methods for recovering the file's Data Encryption Key.

This project currently implements only:

```text
Password
```

Certificate-based and UPC-based recovery are not implemented.

New containers generated by this project are therefore password-only.

## Cryptographic overview

For decryption:

```text
password
   |
   | UTF-16LE
   v
 SHA-256
   |
   v
256-bit KEK
   |
   | AES-256-ECB decrypt
   v
128-bit DEK
   |
   | SHA-256 verification
   v
verified DEK
   |
   | AES-128-CBC
   | deterministic IV per chunk
   v
plaintext
```

For encryption:

```text
random 128-bit DEK
       |
       +--------------------------+
       |                          |
       v                          v
 SHA-256(DEK)              AES-128-CBC payload
       |                          |
       v                          v
 header hash                 encrypted data

password
   |
 UTF-16LE
   |
 SHA-256
   |
   v
256-bit KEK
   |
 AES-256-ECB encrypt
   |
   v
wrapped DEK
   |
   v
XML header
```

## Safety during recovery

When decrypting valuable data, keep a backup of the encrypted files until the recovered files have been independently verified.

A recommended first pass is:

```bash
python3 rmau.py decrypt -p password.txt -r /backup
```

Inspect several recovered files and compare sizes, hashes, or contents where possible.

Only then use:

```bash
python3 rmau.py decrypt -p password.txt -r --delete /backup
```

if removal of the encrypted copies is desired.

## Suggested repository layout

```text
symantec-rmau/
├── rmau.py
├── README.md
├── requirements.txt
├── LICENSE
└── .gitignore
```

`requirements.txt`:

```text
cryptography
```

A minimal `.gitignore`:

```gitignore
__pycache__/
*.pyc
password.txt
*.tmp
```

Do not commit passwords, decrypted confidential data, private keys, or proprietary encrypted test material.

## Compatibility

The implementation was developed from observed files produced by Symantec removable-media encryption software.

Different product versions may use different:

- algorithms;
- header layouts;
- key derivation methods;
- `SHAFunction` values;
- `hashmethod` values;
- alignment sizes;
- key recovery mechanisms.

The current implementation should therefore reject unknown formats rather than assume that every Symantec encrypted container uses the same scheme.

Reports and sanitized test vectors from other versions are useful for extending compatibility.

## Testing

A particularly useful interoperability test is deterministic re-encryption.

For an existing Symantec container:

```text
original encrypted container
        |
        v
     decrypt
        |
        v
     plaintext
        |
        | same original DEK
        v
     encrypt
        |
        v
reconstructed encrypted container
```

When the original header and cryptographic parameters are preserved, the reconstructed file should be identical to the source.

This test has been successfully performed on the analyzed samples, including a multi-megabyte binary file.

For newly generated containers, the implementation additionally performs an encrypt/decrypt round-trip and verifies that the recovered plaintext is byte-for-byte identical to the source.

## Scope

This project is intended for:

- recovering your own encrypted data;
- migrating data away from legacy removable-media encryption;
- interoperability;
- archival recovery;
- digital preservation;
- security research.

It is not intended to bypass authentication.

A valid password is required for password-protected containers unless another legitimate key recovery mechanism is implemented separately.

## Original software

The file format implemented here is associated with **Symantec Endpoint Encryption Removable Media Encryption** and the **Removable Media Access Utility**.

Symantec enterprise security products and related intellectual property are currently associated with Broadcom.

This project is an independent interoperability implementation and contains no Symantec/Broadcom source code.

## Disclaimer

This project is not affiliated with, endorsed by, or supported by Symantec or Broadcom.

All product names and trademarks belong to their respective owners.

The implementation is based on independent analysis of file formats and cryptographic behavior for interoperability and data-recovery purposes.

Use the software only with files and credentials you are authorized to access.

## License

Choose an open-source license appropriate for the repository.

For a small interoperability utility, MIT or Apache-2.0 are both reasonable choices.

For example, when using the MIT License:

```text
SPDX-License-Identifier: MIT
```

can be added to the source file and the complete license text placed in `LICENSE`.
