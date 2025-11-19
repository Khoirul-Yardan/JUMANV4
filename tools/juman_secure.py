#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
juman_secure.py

Manager penyimpanan terenkripsi untuk JuMan (Python).
Fitur utama:
- Inisialisasi data directory dan menyimpan `master.key` terenkripsi dengan password pengguna (PBKDF2).
- Enkripsi/dekripsi berkas menggunakan AES-GCM (master key).
- Menyimpan file terenkripsi ke folder `storage` dengan nama `UUID__orig.ext.jmn`.
- Menyembunyikan file di Windows (atribut DOS hidden/system) bila tersedia.
- Secure overwrite (satu pass zeros) sebelum penghapusan.
- Backup (zip) dan enkripsi backup.

CATATAN: Skrip ini untuk digunakan lokal pada lingkungan pengujian atau produksi Anda sendiri. Jangan gunakan untuk menyerang sistem lain.
"""

import argparse
import base64
import json
import os
import platform
import shutil
import stat
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import constant_time

import secrets

# Default locations (match Java AuthManager: ~/Documents/JuMan)
DATA_DIR = Path.home() / 'Documents' / 'JuMan'
CONFIG_NAME = 'config.json'
MASTER_KEY_ENC = 'master.key.enc'
RECOVERY = 'recovery.txt'
STORAGE_DIRNAME = 'storage'
BACKUP_SUFFIX = '.jumanbackup'

# KDF parameters
PBKDF2_ITER = 200_000
SALT_LEN = 16
AESGCM_IV_LEN = 12


def _derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITER) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode('utf-8'))


def _encrypt_with_key(plaintext: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    iv = secrets.token_bytes(AESGCM_IV_LEN)
    ct = aes.encrypt(iv, plaintext, None)
    return iv + ct


def _decrypt_with_key(data: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    iv = data[:AESGCM_IV_LEN]
    ct = data[AESGCM_IV_LEN:]
    return aes.decrypt(iv, ct, None)


def init_data_dir(data_dir: Path = DATA_DIR, password: Optional[str] = None):
    """Buat data dir dan simpan master key terenkripsi. Jika sudah ada, tidak menimpa.
    Jika tidak diberikan password, master key akan dihasilkan dan disimpan terenkripsi dengan random password file (tidak direkomendasikan).
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    config_path = data_dir / CONFIG_NAME
    storage = data_dir / STORAGE_DIRNAME
    storage.mkdir(parents=True, exist_ok=True)

    if config_path.exists() and (data_dir / MASTER_KEY_ENC).exists():
        print('Data dir sudah terinisialisasi')
        return

    # buat master key
    master_key = secrets.token_bytes(32)

    # buat salt & derivation
    salt = secrets.token_bytes(SALT_LEN)
    if password is None:
        # generate a random password and store to recovery.txt (not ideal)
        password = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
        print('Generated random password (stored in recovery):', password)
    dk = _derive_key(password, salt)
    enc = _encrypt_with_key(master_key, dk)

    # simpan master key terenkripsi
    with open(data_dir / MASTER_KEY_ENC, 'wb') as f:
        f.write(enc)

    # simpan config (salt & iterations, base64)
    config = {'salt': base64.b64encode(salt).decode('ascii'), 'iterations': PBKDF2_ITER}
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f)

    # simpan recovery token
    rec = base64.b64encode(secrets.token_bytes(24)).decode('ascii')
    with open(data_dir / RECOVERY, 'w', encoding='utf-8') as f:
        f.write(rec)
    print('Inisialisasi selesai. Data dir:', str(data_dir))


def load_master_key(data_dir: Path = DATA_DIR, password: str = None) -> bytes:
    data_dir = Path(data_dir)
    cfg = data_dir / CONFIG_NAME
    mk_enc = data_dir / MASTER_KEY_ENC
    if not cfg.exists() or not mk_enc.exists():
        raise FileNotFoundError('Config atau master key terenkripsi tidak ditemukan; jalankan init dulu')
    with open(cfg, 'r', encoding='utf-8') as f:
        config = json.load(f)
    salt = base64.b64decode(config['salt'])
    iterations = config.get('iterations', PBKDF2_ITER)
    if password is None:
        raise ValueError('Password diperlukan untuk membuka master key')
    dk = _derive_key(password, salt, iterations)
    enc = mk_enc.read_bytes()
    try:
        mk = _decrypt_with_key(enc, dk)
    except Exception as e:
        raise ValueError('Gagal mendekripsi master key — password mungkin salah') from e
    return mk


def _sanitize_filename(fn: str) -> str:
    return ''.join(c if c.isalnum() or c in '._-' else '_' for c in fn)


def store_encrypted(input_path: Path, password: str, data_dir: Path = DATA_DIR) -> str:
    data_dir = Path(data_dir)
    storage = data_dir / STORAGE_DIRNAME
    storage.mkdir(parents=True, exist_ok=True)
    mk = load_master_key(data_dir, password)

    idstr = str(uuid.uuid4())
    orig = _sanitize_filename(input_path.name)
    out_name = idstr + '__' + orig + '.jmn'
    out_path = storage / out_name

    # encrypt file with master key
    aes = AESGCM(mk)
    iv = secrets.token_bytes(AESGCM_IV_LEN)
    with open(input_path, 'rb') as fin, open(out_path, 'wb') as fout:
        fout.write(iv)
        while True:
            chunk = fin.read(8192)
            if not chunk:
                break
            # we will encrypt whole data at once: simpler approach — read all
            # But to support streaming encryption we need different API. For simplicity, read whole.
    # simpler: encrypt whole file in-memory (acceptable for moderate file sizes).
    data = (input_path.read_bytes())
    ct = AESGCM(mk).encrypt(iv, data, None)
    out_path.write_bytes(iv + ct)

    # set hidden attributes on Windows
    try:
        if platform.system().lower().startswith('win'):
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_SYSTEM = 0x04
            attrs = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
            ctypes.windll.kernel32.SetFileAttributesW(str(out_path), attrs)
    except Exception:
        pass

    # best-effort delete original securely
    try:
        secure_overwrite_and_delete(input_path)
    except Exception:
        try:
            input_path.unlink()
        except Exception:
            pass
    return out_name


def decrypt_to_temp(stored_filename: str, password: str, data_dir: Path = DATA_DIR) -> Path:
    data_dir = Path(data_dir)
    storage = data_dir / STORAGE_DIRNAME
    p = find_stored_path(storage, stored_filename)
    if p is None:
        raise FileNotFoundError('Stored file not found')
    mk = load_master_key(data_dir, password)
    raw = p.read_bytes()
    iv = raw[:AESGCM_IV_LEN]
    ct = raw[AESGCM_IV_LEN:]
    data = AESGCM(mk).decrypt(iv, ct, None)
    # determine extension
    orig = stored_filename
    if '__' in p.name:
        orig = p.name.split('__', 1)[1]
        if orig.endswith('.jmn'):
            orig = orig[:-4]
    suffix = ''.join(['.' + orig.split('.')[-1]]) if '.' in orig else '.dec'
    tmp = Path(tempfile.mkstemp(suffix=suffix)[1])
    tmp.write_bytes(data)
    tmp.unlink = tmp.unlink  # keep default
    return tmp


def find_stored_path(storage_dir: Path, stored_filename: str) -> Optional[Path]:
    direct = storage_dir / stored_filename
    if direct.exists():
        return direct
    alt = storage_dir / (stored_filename + '.jmn')
    if alt.exists():
        return alt
    for p in storage_dir.iterdir():
        if not p.is_file():
            continue
        if p.name.lower() == stored_filename.lower() or p.name.lower() == (stored_filename + '.jmn').lower():
            return p
        if p.name.startswith(stored_filename):
            return p
        if '__' in p.name:
            idpart = p.name.split('__', 1)[0]
            if idpart.lower() == stored_filename.lower():
                return p
    return None


def list_stored(data_dir: Path = DATA_DIR):
    storage = Path(data_dir) / STORAGE_DIRNAME
    if not storage.exists():
        return []
    return [p.name for p in storage.iterdir() if p.is_file()]


def secure_overwrite_and_delete(path: Path, passes: int = 1):
    if not path.exists():
        return
    size = path.stat().st_size
    with open(path, 'r+b') as f:
        for _ in range(passes):
            f.seek(0)
            remaining = size
            while remaining > 0:
                chunk = os.urandom(min(8192, remaining))
                f.write(chunk)
                remaining -= len(chunk)
            f.flush()
            os.fsync(f.fileno())
    try:
        path.unlink()
    except Exception:
        pass


def delete_stored(stored_filename: str, password: str, data_dir: Path = DATA_DIR) -> bool:
    storage = Path(data_dir) / STORAGE_DIRNAME
    p = find_stored_path(storage, stored_filename)
    if p is None:
        return False
    try:
        secure_overwrite_and_delete(p)
    except Exception:
        try:
            p.unlink()
        except Exception:
            return False
    return True


def create_encrypted_backup(password: str, data_dir: Path = DATA_DIR, out_name: Optional[str] = None) -> Path:
    data_dir = Path(data_dir)
    storage = data_dir / STORAGE_DIRNAME
    if out_name is None:
        out_name = 'juman_backup_' + uuid.uuid4().hex + '.zip'
    zip_path = data_dir / out_name
    # create zip of storage and config (do not include master.key.enc)
    import zipfile
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        if storage.exists():
            for p in storage.rglob('*'):
                if p.is_file():
                    zf.write(p, arcname=str(Path('storage') / p.relative_to(storage)))
        cfg = data_dir / CONFIG_NAME
        if cfg.exists():
            zf.write(cfg, arcname='config.json')
        rec = data_dir / RECOVERY
        if rec.exists():
            zf.write(rec, arcname='recovery.txt')

    # encrypt zip with master key
    mk = load_master_key(data_dir, password)
    data = zip_path.read_bytes()
    enc = _encrypt_with_key(data, mk)
    out_enc = data_dir / (zip_path.name + BACKUP_SUFFIX)
    out_enc.write_bytes(enc)
    try:
        zip_path.unlink()
    except Exception:
        pass
    return out_enc


def restore_encrypted_backup(enc_file: Path, password: str, data_dir: Path = DATA_DIR):
    data_dir = Path(data_dir)
    mk = load_master_key(data_dir, password)
    enc = Path(enc_file).read_bytes()
    try:
        zipbytes = _decrypt_with_key(enc, mk)
    except Exception as e:
        raise ValueError('Gagal mendekripsi backup: kunci mungkin salah atau file korup') from e
    # write to temp zip and extract
    import zipfile
    tmp = Path(tempfile.mkstemp(suffix='.zip')[1])
    tmp.write_bytes(zipbytes)
    with zipfile.ZipFile(tmp, 'r') as zf:
        zf.extractall(data_dir)
    try:
        tmp.unlink()
    except Exception:
        pass


def cli():
    p = argparse.ArgumentParser(description='JuMan secure manager (Python)')
    p.add_argument('--data-dir', default=str(DATA_DIR))
    sub = p.add_subparsers(dest='cmd')

    init = sub.add_parser('init')
    init.add_argument('--password', help='Password untuk mengenkripsi master key (wajib)')

    store = sub.add_parser('store')
    store.add_argument('file', help='File untuk disimpan (dienkripsi)')
    store.add_argument('--password', required=True)

    ls = sub.add_parser('list')

    get = sub.add_parser('get')
    get.add_argument('stored_name')
    get.add_argument('--password', required=True)
    get.add_argument('--out', help='Path tujuan untuk mengekspor file')

    dele = sub.add_parser('delete')
    dele.add_argument('stored_name')
    dele.add_argument('--password', required=True)

    backup = sub.add_parser('backup')
    backup.add_argument('--password', required=True)
    backup.add_argument('--outname')

    restore = sub.add_parser('restore')
    restore.add_argument('file')
    restore.add_argument('--password', required=True)

    args = p.parse_args()
    dd = Path(args.data_dir)
    if args.cmd == 'init':
        if not args.password:
            print('Password required for init')
            return
        init_data_dir(dd, args.password)
    elif args.cmd == 'store':
        n = store_encrypted(Path(args.file), args.password, dd)
        print('Stored as', n)
    elif args.cmd == 'list':
        for s in list_stored(dd):
            print(s)
    elif args.cmd == 'get':
        tmp = decrypt_to_temp(args.stored_name, args.password, dd)
        if args.out:
            shutil.move(str(tmp), args.out)
            print('Exported to', args.out)
        else:
            print('Decrypted to temp file:', tmp)
    elif args.cmd == 'delete':
        ok = delete_stored(args.stored_name, args.password, dd)
        print('Deleted' if ok else 'Not found')
    elif args.cmd == 'backup':
        out = create_encrypted_backup(args.password, dd, args.outname)
        print('Backup created:', out)
    elif args.cmd == 'restore':
        restore_encrypted_backup(Path(args.file), args.password, dd)
        print('Restore completed')
    else:
        p.print_help()


if __name__ == '__main__':
    cli()
