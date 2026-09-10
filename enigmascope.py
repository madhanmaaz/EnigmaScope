import argparse
import getpass
import glob
import hashlib
import json
import mimetypes
import os
import re
import secrets
import struct
import sys
from datetime import datetime

import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tabulate import tabulate

VERSION = "2.0.0"
MAGIC_FOOTER = b"ENIGMA1\x00"
MAGIC_META = b"ENIGMETA"
MAGIC_ENTRY = b"ENIGENTR"
FOOTER_FMT = ">QQ8s"
FOOTER_SIZE = struct.calcsize(FOOTER_FMT)  # 24
COPY_CHUNK = 1 << 20  # 1 MiB

SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LEN = 2**14, 8, 1, 32


# crypto
class Crypto:
    @staticmethod
    def deriveKey(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=KEY_LEN,
        )

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(key).encrypt(nonce, data, None)

    @staticmethod
    def decrypt(blob: bytes, key: bytes) -> bytes:
        return AESGCM(key).decrypt(blob[:12], blob[12:], None)

    @staticmethod
    def createVerifier(key: bytes) -> str:
        """Create an encrypted password-verification token."""
        challenge = secrets.token_bytes(16)
        verifier = Crypto.encrypt(challenge, key)
        return verifier.hex()

    @staticmethod
    def verifyPassword(token: str, key: bytes) -> bool:
        """Verify that the supplied key can decrypt the verifier."""
        try:
            Crypto.decrypt(bytes.fromhex(token), key)
            return True
        except (ValueError, cryptography.exceptions.InvalidTag):
            return False


# low-level I/O
class LLIO:
    @staticmethod
    def writeMetadata(f, salt: bytes, token: str):
        tb = token.encode()
        f.write(MAGIC_META)
        f.write(struct.pack(">I", len(salt)))
        f.write(salt)
        f.write(struct.pack(">I", len(tb)))
        f.write(tb)

    @staticmethod
    def writeFooter(f, startOffset: int, count: int):
        f.write(struct.pack(FOOTER_FMT, startOffset, count, MAGIC_FOOTER))

    @staticmethod
    def writeEntry(f, header: dict, encryptedData: bytes) -> int:
        """Write one entry blob; return the absolute file offset of encrypted_data."""
        headerBytes = json.dumps(header).encode()
        f.write(MAGIC_ENTRY)
        f.write(struct.pack(">I", len(headerBytes)))
        f.write(headerBytes)
        f.write(struct.pack(">Q", len(encryptedData)))
        dataOffset = f.tell()
        f.write(encryptedData)
        return dataOffset

    @staticmethod
    def readMetadata(f):
        if f.read(8) != MAGIC_META:
            raise ValueError("Corrupt capsule: bad META magic.")

        (n,) = struct.unpack(">I", f.read(4))
        salt = f.read(n)
        (n,) = struct.unpack(">I", f.read(4))
        token = f.read(n).decode()
        return salt, token

    @staticmethod
    def readFooter(f, filesize: int):
        f.seek(filesize - FOOTER_SIZE)
        startOffset, count, magic = struct.unpack(FOOTER_FMT, f.read(FOOTER_SIZE))

        if magic != MAGIC_FOOTER:
            raise ValueError("Not a valid EnigmaScope capsule.")

        return startOffset, count


# capsule operations
class Capsule:
    @staticmethod
    def scanEntries(f, count: int) -> list:
        """Read headers + record data offsets. Skips over encrypted_data — never loads it."""
        entries = []
        for _ in range(count):
            if f.read(8) != MAGIC_ENTRY:
                raise ValueError("Corrupt capsule: bad ENTRY magic.")

            (n,) = struct.unpack(">I", f.read(4))
            header = json.loads(f.read(n))
            (dataLen,) = struct.unpack(">Q", f.read(8))
            dataOffset = f.tell()
            f.seek(dataLen, 1)  # skip the blob
            entries.append(
                {"header": header, "dataOffset": dataOffset, "dataLen": dataLen}
            )

        return entries

    @staticmethod
    def init(capsulePath: str, salt: bytes, token: str) -> None:
        """Stamp META + empty FOOTER after the existing image bytes."""
        startOffset = os.path.getsize(capsulePath)

        with open(capsulePath, "ab") as f:
            LLIO.writeMetadata(f, salt, token)
            LLIO.writeFooter(f, startOffset, 0)

    @staticmethod
    def isNew(capsulePath: str) -> bool:
        if os.path.getsize(capsulePath) < FOOTER_SIZE:
            return True

        with open(capsulePath, "rb") as f:
            f.seek(-FOOTER_SIZE, 2)
            _, _, magic = struct.unpack(FOOTER_FMT, f.read(FOOTER_SIZE))
        return magic != MAGIC_FOOTER

    @staticmethod
    def open(capsulePath: str):
        """Return (startOffset, salt, token, entries). No bulk data in RAM."""
        sz = os.path.getsize(capsulePath)
        with open(capsulePath, "rb") as f:
            startOffset, count = LLIO.readFooter(f, sz)
            f.seek(startOffset)
            salt, token = LLIO.readMetadata(f)
            entries = Capsule.scanEntries(f, count)

        return startOffset, salt, token, entries

    @staticmethod
    def append(
        capsulePath: str,
        header: dict,
        encryptedData: bytes,
        startOffset: int,
        newCount: int,
    ):
        """
        Seek to the old footer position, overwrite it with the new entry,
        then write a fresh footer. Image bytes are never read.
        Returns the data_offset of the new entry.
        """
        sz = os.path.getsize(capsulePath)
        with open(capsulePath, "r+b") as f:
            f.seek(sz - FOOTER_SIZE)  # overwrite old footer
            dataOffset = LLIO.writeEntry(f, header, encryptedData)
            LLIO.writeFooter(f, startOffset, newCount)

        return dataOffset

    @staticmethod
    def compact(
        capsulePath: str, startOffset: int, salt: bytes, token: str, keep: list
    ) -> list:
        """
        Rewrite the capsule keeping only `keep` entries.
        Image bytes are copied in 1 MiB chunks — never fully in RAM.
        `keep` entries are read one at a time from the source file.
        Returns updated entries list with corrected data_offsets.
        """
        tmp = capsulePath + ".enigmatmp"
        updated = []

        try:
            with open(capsulePath, "rb") as src, open(tmp, "wb") as dst:
                # copy image in chunks
                remaining = startOffset
                while remaining > 0:
                    chunk = src.read(min(COPY_CHUNK, remaining))
                    dst.write(chunk)
                    remaining -= len(chunk)

                LLIO.writeMetadata(dst, salt, token)

                for e in keep:
                    src.seek(e["dataOffset"])
                    blob = src.read(e["dataLen"])
                    newOffset = LLIO.writeEntry(dst, e["header"], blob)
                    updated.append({**e, "dataOffset": newOffset})

                LLIO.writeFooter(dst, startOffset, len(updated))

            os.replace(tmp, capsulePath)
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

        return updated

    @staticmethod
    def list(entries: list) -> None:
        if not entries:
            print("no files stored.")
            return

        rows = [
            [i, e["header"]["name"], e["header"]["time"], e["header"]["size"]]
            for i, e in enumerate(entries)
        ]

        print(
            "\n",
            tabulate(
                rows,
                headers=["ID", "FILE", "TIME", "SIZE"],
                colalign=("right", "left", "left", "right"),
            ),
            "\n",
        )

    @staticmethod
    def resolve(arg: str, total: int):
        if arg == "*":
            return list(range(total))
        try:
            idx = int(arg)
            return [idx] if 0 <= idx < total else None
        except ValueError:
            return None


HELP = """
+======== COMMANDS ========+
help               This menu.
q                  Exit.
clear              Clear screen.

list               List all files.
write  <FILE ...>  Append file(s). Supports globs and multiple paths.
dwrite <FILE ...>  Same as write but deletes source file(s) after.
read   <ID | *>    Decrypt and export file(s).
delete <ID | *>    Remove file(s) from capsule.
"""


def filterFilename(filename: str):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", filename.replace(" ", "_"))


def repl(
    path: str, startOffset: int, salt: bytes, key: bytes, token: str, entries: list
) -> None:
    name = os.path.basename(path).replace(".", "_")
    outputDir = os.path.join(os.path.dirname(os.path.abspath(path)), name)

    print(HELP)

    while True:
        try:
            raw = input(f"[{name}]> ").strip()
        except EOFError:
            break

        if not raw:
            continue

        parts = raw.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "q":
            print("Bye.")
            break

        elif cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")

        elif cmd == "help":
            print(HELP)

        elif cmd == "list":
            Capsule.list(entries)

        elif cmd in ("write", "dwrite"):
            if not args:
                print(f"Usage: {cmd} <FILE ...>")
                continue

            targets = []
            for a in args:
                expanded = glob.glob(a)
                targets.extend(expanded if expanded else [a])

            for fp in targets:
                if not os.path.isfile(fp):
                    print(f"[-] not a file: {fp}")
                    continue

                try:
                    with open(fp, "rb") as fh:
                        rawData = fh.read()

                    ft = mimetypes.guess_type(fp)[0] or "application/octet-stream"
                    enc = Crypto.encrypt(rawData, key)
                    header = {
                        "name": filterFilename(os.path.basename(fp)),
                        "time": str(datetime.now()),
                        "size": len(rawData),
                        "filetype": ft,
                    }
                    doff = Capsule.append(
                        path, header, enc, startOffset, len(entries) + 1
                    )
                    entries.append(
                        {"header": header, "dataOffset": doff, "dataLen": len(enc)}
                    )
                    del rawData, enc

                    if cmd == "dwrite":
                        os.remove(fp)
                        print(f"[+] {header['name']} written and deleted.")
                    else:
                        print(f"[+] {header['name']} written.")
                except Exception as ex:
                    print(f"[-] {fp}: {ex}")

        elif cmd == "read":
            if not args:
                print("Usage: read <ID | *>")
                continue

            ids = Capsule.resolve(args[0], len(entries))
            if ids is None:
                print(f"[-] Invalid id '{args[0]}'.")
                continue

            with open(path, "rb") as f:
                print("\n[+] Decrypting...")

                for idx in ids:
                    e = entries[idx]
                    h = e["header"]

                    try:
                        f.seek(e["dataOffset"])
                        blob = f.read(e["dataLen"])  # one entry at a time
                        data = Crypto.decrypt(blob, key)
                        del blob
                    except Exception:
                        print(f"[-] Decryption failed for [{idx}] {h['name']}.")
                        continue

                    os.makedirs(outputDir, exist_ok=True)
                    out = os.path.join(outputDir, f"{idx}_{h['name']}")
                    with open(out, "wb") as fh:
                        fh.write(data)
                    print(f"[+] ({idx}) {h['name']} -> {out}")
                    del data

                print("[+] done.\n")

        elif cmd == "delete":
            if not args:
                print("  Usage: delete <ID | *>")
                continue

            ids = Capsule.resolve(args[0], len(entries))
            if ids is None:
                print(f"[-] Invalid id '{args[0]}'.")
                continue

            idSet = set(ids)
            keep = [e for i, e in enumerate(entries) if i not in idSet]

            for idx in sorted(ids):
                print(f"[+] deleted [{idx}] {entries[idx]['header']['name']}")
            entries[:] = Capsule.compact(path, startOffset, salt, token, keep)

        else:
            print(f"[-] Unknown command '{cmd}'. Type 'help'.")


def main():
    parser = argparse.ArgumentParser(
        description="EnigmaScope — encrypted file capsule inside an image."
    )

    parser.add_argument(
        "-v", "--version", action="version", version=f"EnigmaScope {VERSION}"
    )
    parser.add_argument(
        "-l",
        "--load",
        required=True,
        help="Capsule image. ex: wallpaper.jpg, app.exe, run.dll, movie.mp4, sample.pdf ...etc",
    )

    args = parser.parse_args()
    capsulePath = args.load

    if not os.path.exists(capsulePath):
        print(f"[-] capsule not found: {capsulePath}")
        return

    ft = mimetypes.guess_type(capsulePath)[0]
    if ft and ft.startswith("text"):
        print(f"[-] capsule is {ft}: {capsulePath} — don't use text/* files.")
        return

    try:
        if Capsule.isNew(capsulePath):
            print("[*] New capsule detected.")

            while True:
                pw = getpass.getpass("Set password     : ")
                pw2 = getpass.getpass("Confirm password : ")

                if pw == pw2:
                    break
                print("[-] Passwords don't match. Try again.")

            salt = secrets.token_bytes(16)
            key = Crypto.deriveKey(pw, salt)
            token = Crypto.createVerifier(key)

            Capsule.init(capsulePath, salt, token)
            startOffset, salt, token, entries = Capsule.open(capsulePath)
            print("[+] Capsule initialised.\n")
        else:
            startOffset, salt, token, entries = Capsule.open(capsulePath)
            pw = getpass.getpass("Password: ")
            key = Crypto.deriveKey(pw, salt)

            if not Crypto.verifyPassword(token, key):
                print("[-] Invalid password")
                return

            print(f"[+] Unlocked — {len(entries)} file(s) stored.")

        repl(capsulePath, startOffset, salt, key, token, entries)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt — enigmaScope exit.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] {e}")


main()
