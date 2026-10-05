#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import base64
import hashlib
import re
import secrets
import struct
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

ALIGN = 512


def aes(data, key, mode, encrypt=False):
    cipher = Cipher(algorithms.AES(key), mode)
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


def chunk_iv(n):
    words = []

    for _ in range(4):
        n = (
            0x3039
            - (n * 0x3E39B193 & 0xFFFFFFFF)
        ) & 0x7FFFFFFF

        words.append(n)

    return struct.pack("<4I", *words)


def payload_start(header_size, alignment):
    """
    Return the first encrypted payload offset.

    The payload is aligned to AlignmentLength and at least
    8 bytes must remain between the XML header and payload,
    because the padding count is stored at start - 8.
    """
    start = (
        (header_size + alignment - 1)
        // alignment
        * alignment
    )

    if start - header_size < 8:
        start += alignment

    return start


def crypt_payload(data, key, alignment, encrypt):
    out = bytearray()

    for n, pos in enumerate(range(0, len(data), alignment)):
        out += aes(
            data[pos:pos + alignment],
            key,
            modes.CBC(chunk_iv(n)),
            encrypt,
        )

    return bytes(out)


def parse(path):
    raw = path.read_bytes()

    text = raw[:65536].decode(
        "utf-16le",
        errors="ignore",
    )

    m = re.search(
        r"GETRSFileHeaderSize=(0x[0-9A-Fa-f]+|\d+)",
        text,
    )

    if not m:
        raise ValueError("formato non riconosciuto")

    header_size = int(m.group(1), 0)

    xml = raw[:header_size].decode(
        "utf-16le",
        errors="ignore",
    )

    def tag(name):
        m = re.search(
            fr"<{name}>(.*?)</{name}>",
            xml,
            re.S,
        )
        return m.group(1) if m else None

    wrapped_keys = re.search(
        r"<WrappedKeys\b([^>]*)>",
        xml,
    )

    if not wrapped_keys:
        raise ValueError("WrappedKeys non trovato")

    attributes = wrapped_keys.group(1)

    def attr(name):
        m = re.search(
            fr'{name}="([^"]+)"',
            attributes,
        )

        if not m:
            raise ValueError(
                f"attributo WrappedKeys mancante: {name}"
            )

        return m.group(1)

    wrapped = re.search(
        r"<Password\b[^>]*>"
        r".*?<wrappedkey[^>]*>"
        r"(.*?)"
        r"</wrappedkey>",
        xml,
        re.S,
    )

    if not wrapped:
        raise ValueError(
            "wrappedkey Password non trovato"
        )

    alignment_text = tag("AlignmentLength")

    if alignment_text is None:
        raise ValueError(
            "AlignmentLength non trovato"
        )

    alignment = int(alignment_text)

    start = payload_start(
        header_size,
        alignment,
    )

    if start > len(raw):
        raise ValueError(
            "offset payload oltre la fine del file"
        )

    padding = int.from_bytes(
        raw[start - 8:start - 6],
        "little",
    )

    if padding > 15:
        raise ValueError(
            f"padding non valido: {padding}"
        )

    return {
        "raw": raw,
        "xml": xml,
        "header": header_size,
        "alignment": alignment,
        "start": start,
        "padding": padding,
        "filename": tag("filename"),
        "hash": base64.b64decode(
            attr("hash")
        ),
        "wrapped": base64.b64decode(
            wrapped.group(1)
        ),
    }


def password(path):
    if path:
        return path.read_text(
            encoding="utf-8"
        ).rstrip("\r\n")

    return getpass("Password: ")


def get_dek(info, pwd):
    kek = hashlib.sha256(
        pwd.encode("utf-16le")
    ).digest()

    dek = aes(
        info["wrapped"],
        kek,
        modes.ECB(),
    )

    if (
        hashlib.sha256(dek).digest()
        != info["hash"]
    ):
        raise ValueError("password errata")

    return dek


def decrypt_one(
    src,
    pwd,
    delete=False,
    force=False,
):
    info = parse(src)

    dek = get_dek(
        info,
        pwd,
    )

    data = crypt_payload(
        info["raw"][info["start"]:],
        dek,
        info["alignment"],
        False,
    )

    padding = info["padding"]

    if padding:
        if padding > len(data):
            raise ValueError(
                "padding oltre la dimensione del file"
            )

        data = data[:-padding]

    dst = src.with_name(
        src.name[:-4]
        if src.name.lower().endswith(".xml")
        else src.name + ".decrypted"
    )

    if dst.exists() and not force:
        raise FileExistsError(
            f"esiste già: {dst}"
        )

    tmp = dst.with_name(
        dst.name + ".tmp"
    )

    try:
        tmp.write_bytes(data)
        tmp.replace(dst)
    finally:
        if tmp.exists():
            tmp.unlink()

    if delete:
        src.unlink()

    return dst


def make_xml(filename, dek, wrapped):
    dek_hash = base64.b64encode(
        hashlib.sha256(dek).digest()
    ).decode()

    wrapped_b64 = base64.b64encode(
        wrapped
    ).decode()

    iv_b64 = base64.b64encode(
        secrets.token_bytes(16)
    ).decode()

    created = datetime.now(
        timezone.utc
    ).strftime(
        "%a, %d %b %Y %H:%M:%S UT+0000"
    )

    template = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<!--GETRSFileHeaderSize={size}-->'
        '<GETEncryptedDataFile version="x.x.x">'
        '<FileInformation>'
        f"<filename>{filename}</filename>"
        f"<created>{created}</created>"
        "</FileInformation>"
        f"<AlignmentLength>{ALIGN}</AlignmentLength>"
        '<WrappedKeys SHAFunction="hash2" '
        f'iv="{iv_b64}" '
        f'hash="{dek_hash}">'
        '<Password hashmethod="kdf2">'
        f"<wrappedkey>{wrapped_b64}</wrappedkey>"
        "</Password>"
        "</WrappedKeys>"
        "</GETEncryptedDataFile>"
    )

    size = "0x00000000"

    while True:
        xml = template.format(
            size=size
        )

        encoded = xml.encode(
            "utf-16le"
        )

        new_size = (
            f"0x{len(encoded):08X}"
        )

        if new_size == size:
            return encoded

        size = new_size


def encrypt_one(
    src,
    pwd,
    force=False,
    verify=True,
):
    data = src.read_bytes()

    padding = (-len(data)) & 15

    plain = (
        data
        + b"\0" * padding
    )

    dek = secrets.token_bytes(16)

    kek = hashlib.sha256(
        pwd.encode("utf-16le")
    ).digest()

    wrapped = aes(
        dek,
        kek,
        modes.ECB(),
        True,
    )

    header = make_xml(
        src.name,
        dek,
        wrapped,
    )

    start = payload_start(
        len(header),
        ALIGN,
    )

    metadata = bytearray(
        start - len(header)
    )

    metadata[-8:-6] = (
        padding.to_bytes(
            2,
            "little",
        )
    )

    encrypted = crypt_payload(
        plain,
        dek,
        ALIGN,
        True,
    )

    container = (
        header
        + metadata
        + encrypted
    )

    dst = src.with_name(
        src.name + ".XML"
    )

    if dst.exists() and not force:
        raise FileExistsError(
            f"esiste già: {dst}"
        )

    if verify:
        check = crypt_payload(
            encrypted,
            dek,
            ALIGN,
            False,
        )

        if padding:
            check = check[:-padding]

        if check != data:
            raise ValueError(
                "self-test fallito"
            )

    tmp = dst.with_name(
        dst.name + ".tmp"
    )

    try:
        tmp.write_bytes(container)
        tmp.replace(dst)
    finally:
        if tmp.exists():
            tmp.unlink()

    return dst


def files(path, recursive, encrypted):
    if path.is_file():
        return [path]

    pattern = (
        "**/*"
        if recursive
        else "*"
    )

    return sorted(
        item
        for item in path.glob(pattern)
        if item.is_file()
        and (
            item.name.lower().endswith(".xml")
            if encrypted
            else not item.name.lower().endswith(".xml")
        )
    )


def cmd_decrypt(args):
    pwd = password(
        args.password_file
    )

    sources = files(
        args.path,
        args.recursive,
        True,
    )

    ok = 0
    errors = 0

    for src in sources:
        try:
            dst = decrypt_one(
                src,
                pwd,
                args.delete,
                args.force,
            )

            print(
                f"OK  {src} -> {dst}"
            )

            ok += 1

        except Exception as exc:
            print(
                f"ERR {src}: {exc}"
            )

            errors += 1

    print(
        f"\nDecifrati: {ok}  "
        f"Errori: {errors}"
    )

    if errors:
        raise SystemExit(1)


def cmd_encrypt(args):
    pwd = password(
        args.password_file
    )

    sources = files(
        args.path,
        args.recursive,
        False,
    )

    ok = 0
    errors = 0

    for src in sources:
        try:
            dst = encrypt_one(
                src,
                pwd,
                args.force,
            )

            print(
                f"OK  {src} -> {dst}"
            )

            ok += 1

        except Exception as exc:
            print(
                f"ERR {src}: {exc}"
            )

            errors += 1

    print(
        f"\nCifrati: {ok}  "
        f"Errori: {errors}"
    )

    if errors:
        raise SystemExit(1)


def cmd_info(args):
    info = parse(args.path)

    print(
        f"File       : {args.path}"
    )
    print(
        f"Originale  : {info['filename']}"
    )
    print(
        f"Header     : {info['header']} byte"
    )
    print(
        f"Alignment  : {info['alignment']}"
    )
    print(
        f"Data       : 0x{info['start']:x}"
    )
    print(
        "Ciphertext : "
        f"{len(info['raw']) - info['start']} byte"
    )
    print(
        f"Padding    : {info['padding']}"
    )
    print(
        f"SHA-256 DEK: {info['hash'].hex()}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Symantec Removable Media "
            "Access Utility compatible tool"
        )
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    for name, func in (
        ("encrypt", cmd_encrypt),
        ("decrypt", cmd_decrypt),
    ):
        command = sub.add_parser(
            name
        )

        command.add_argument(
            "path",
            type=Path,
        )

        command.add_argument(
            "-p",
            "--password-file",
            type=Path,
        )

        command.add_argument(
            "-r",
            "--recursive",
            action="store_true",
        )

        command.add_argument(
            "--force",
            action="store_true",
        )

        if name == "decrypt":
            command.add_argument(
                "--delete",
                action="store_true",
            )

        command.set_defaults(
            func=func
        )

    command = sub.add_parser(
        "info"
    )

    command.add_argument(
        "path",
        type=Path,
    )

    command.set_defaults(
        func=cmd_info
    )

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
