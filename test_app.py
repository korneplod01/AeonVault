# test_app.py
import os
import sqlite3
import tempfile
from generator import PasswordGenerator
from storage import AESEncryptor, PasswordStorage, LogStorage


class DummyLogger:
    def __init__(self):
        self.records = []

    def log(self, action: str, service: str = ""):
        self.records.append((action, service))


def test_aes_encrypt_decrypt_roundtrip():
    enc = AESEncryptor("test-password")
    original = "секретная_строка"
    encrypted = enc.encrypt(original)
    assert isinstance(encrypted, str)
    assert encrypted != original

    decrypted = enc.decrypt(encrypted)
    assert decrypted == original


def test_aes_decrypt_invalid_data_raises():
    enc = AESEncryptor("test-password")
    bad_data = "not-base64!"
    try:
        enc.decrypt(bad_data)
        raised = False
    except Exception:
        raised = True
    assert raised


def test_password_generator_segmented_basic():
    gen = PasswordGenerator(DummyLogger())
    pwd = gen.generate_segmented_password(segment_length=4, segments_amount=3, separator="-")
    parts = pwd.split("-")
    assert len(parts) == 3
    for p in parts:
        assert len(p) == 4
        assert any(c.isalpha() for c in p)


def test_password_generator_semantic_returns_words():
    gen = PasswordGenerator(DummyLogger())
    pwd, theme, words = gen.generate_semantic_password(password_length=3)
    assert isinstance(pwd, str)
    assert isinstance(theme, str)
    assert len(words) == 3


def test_password_storage_get_unknown_returns_none():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "passwords2.db")
        storage = object.__new__(PasswordStorage)
        storage.db_file = db_path
        storage.salt_file = os.path.join(tmp, "vault_salt.bin")
        storage.hash_file = os.path.join(tmp, "master_hash.txt")
        storage.conn = sqlite3.connect(db_path)
        storage.cursor = storage.conn.cursor()
        storage.crypto = AESEncryptor("test-password", b"1" * 16)
        storage._init_db()

        assert storage.get("no_such_service") is None

        storage.close()


def test_log_storage_writes_row():
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "logs.db")
        logs = LogStorage(log_file=log_path)
        logs.log("test_action", "service1")
        logs.close()

        conn = sqlite3.connect(log_path)
        cur = conn.cursor()
        cur.execute("SELECT action, service FROM logs")
        rows = cur.fetchall()
        conn.close()

        assert ("test_action", "service1") in rows
