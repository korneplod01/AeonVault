import sqlite3
import os
import datetime
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import getpass

class AESEncryptor:
    """Шифрует и расшифровывает строки с помощью AES-GCM.

    Использует PBKDF2 для получения ключа из текстового пароля
    и хранит соль вместе с объектом.
    """
    def __init__(self, password: str, salt: bytes = None):
        """Создает шифратор AES на основе пароля.

        Args:
            password: Текстовый мастер-пароль, из которого будет
                получен ключ шифрования.
            salt: Соль для PBKDF2. Если не указана, генерируется
                случайная соль длиной 16 байт.

        """
        self.salt = salt if salt else get_random_bytes(16)
        # Генерируем ключ 256 бит из пароля
        self.key = PBKDF2(password.encode(), self.salt, dkLen=32, count=100000)
    
    def encrypt(self, text: str) -> str:
        """Шифрует текст с использованием AES-GCM.

        Данные шифруются с генерацией случайного nonce, а затем
        объединяются в одну строку, кодируемую в base64.

        Args:
            text: Исходная строка в открытом виде.

        Returns:
            str: Строка в кодировке base64, содержащая nonce, тег
            аутентичности и зашифрованный текст.
        """
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode())
        # Объединяем nonce + tag + ciphertext в одну строку
        encrypted = cipher.nonce + tag + ciphertext
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_text: str) -> str:
        """Расшифровывает текст, зашифрованный методом encrypt.

        Ожидает строку base64, содержащую nonce, тег и шифртекст.
        При повреждении данных или неверном ключе вызывается исключение.

        Args:
            encrypted_text: Строка base64, полученная методом encrypt.

        Returns:
            str: Расшифрованная строка в открытом виде.

        Raises:
            ValueError: Если данные повреждены или аутентификация
                шифртекста не проходит.
            binascii.Error: Если строка не является корректной base64.
        """
        data = base64.b64decode(encrypted_text.encode())
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

class PasswordStorage:
    """Хранилище паролей с шифрованием и мастер-паролем.

    Пароли и логины сохраняются в SQLite-базе в зашифрованном виде,
    доступ к расшифровке контролируется мастер-паролем.
    """
    def __init__(self, db_file='passwords.db'):
        """Создает или открывает хранилище паролей.

        Настраивает криптографию (создание или проверка мастер-пароля),
        подключается к SQLite-базе и создает таблицы при необходимости.

        Args:
            db_file: Путь к файлу SQLite-БД, где будут храниться
                зашифрованные пароли.

        Raises:
            ValueError: Если пользователь дважды ввел несовпадающие
                значения мастер-пароля при создании хранилища.
            ValueError: Если введен неверный мастер-пароль для
                существующего хранилища.
            FileNotFoundError: Если отсутствует файл с хешем мастер-пароля
                при попытке проверки.
        """
        self.db_file = db_file
        self.salt_file = 'vault_salt.bin'
        self.hash_file = 'master_hash.txt'
        self.conn = None
        self.cursor = None
        self.crypto = None
        self._setup_crypto()
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()
        self._init_db()
    
    def _setup_crypto(self):
        """Настраивает объект шифрования и мастер-пароль.

        Если хранилище уже существует, запрашивает мастер-пароль
        и проверяет его по сохраненному хешу. Если нет — создает
        новый мастер-пароль, соль и файл с хешем.

        Raises:
            ValueError: При неверном вводе мастер-пароля или его
                повторного значения.
            FileNotFoundError: Если файл с хешем не найден
                для существующего хранилища.
        """
        if os.path.exists(self.db_file) and os.path.exists(self.salt_file):
            # Загружаем существующее
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
            
            while True:
                password = getpass.getpass("Введите мастер-пароль: ")
                try:
                    self.crypto = AESEncryptor(password, salt)
                    # Проверяем пароль
                    self._test_password(password)
                    break
                except ValueError:
                    print("Неверный пароль")
        else:
            # Создаем новое
            password = getpass.getpass("Создайте мастер-пароль: ")
            password2 = getpass.getpass("Повторите: ")
            
            if password != password2:
                raise ValueError("Пароли не совпадают")
            
            self.crypto = AESEncryptor(password)

            with open(self.salt_file, 'wb') as f:
                f.write(self.crypto.salt)
            
            with open(self.hash_file, 'w') as f:
                f.write(hashlib.sha256(password.encode()).hexdigest())
            print("Хранилище создано")
    
    def _test_password(self, password_to_test: str):
        """Проверяет мастер-пароль по сохраненному хешу.

        Args:
            password_to_test: Пароль, введенный пользователем
                для проверки доступа.

        Raises:
            ValueError: Если хеш пароля не совпадает с сохраненным.
            FileNotFoundError: Если файл с хешом не найден.
        """
        if os.path.exists(self.hash_file):
            with open(self.hash_file, 'r') as f:
                saved_hash = f.read().strip()
            
            password_to_test_hash = hashlib.sha256(password_to_test.encode()).hexdigest()
            
            if password_to_test_hash != saved_hash:
                raise ValueError("Неверный пароль")
        else:
            raise FileNotFoundError(f"Файл {self.hash_file} не найден")

    def _init_db(self):
        """Создает таблицу паролей в БД при необходимости.

        Таблица содержит сервис (первичный ключ), логин и пароль,
        при этом логин и пароль хранятся в зашифрованном виде.

        Returns:
            None.
        """
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                service TEXT PRIMARY KEY,
                login TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        self.conn.commit()
    
    def save(self, service: str, login: str, password: str):
        """Сохраняет или обновляет зашифрованный пароль в хранилище.

        Args:
            service: Название сервиса, выступает в роли ключа.
            login: Логин пользователя в открытом виде.
            password: Пароль пользователя в открытом виде.

        Returns:
            None.
        """
        enc_login = self.crypto.encrypt(login)
        enc_password = self.crypto.encrypt(password)
        
        self.cursor.execute('''
            INSERT OR REPLACE INTO passwords (service, login, password)
            VALUES (?, ?, ?)
        ''', (service, enc_login, enc_password))
        self.conn.commit()
        print(f"Пароль для {service} сохранен")
    
    def get(self, service: str) -> tuple:
        """Возвращает расшифрованные логин и пароль для сервиса.

        Args:
            service: Название сервиса, для которого нужно получить данные.

        Returns:
            tuple[str, str] | None: Кортеж (login, password), если запись найдена,
            или None, если сервис отсутствует в хранилище.
        """
        self.cursor.execute(
            "SELECT login, password FROM passwords WHERE service = ?", 
            (service,)
        )
        row = self.cursor.fetchone()
        
        if row:
            login = self.crypto.decrypt(row[0])
            password = self.crypto.decrypt(row[1])
            return login, password
        return None
    
    def list_all(self) -> list:
        """Возвращает список всех сохраненных сервисов.

        Returns:
            list[str]: Список названий сервисов, отсортированный по алфавиту.
        """
        self.cursor.execute("SELECT service FROM passwords ORDER BY service")
        return [row[0] for row in self.cursor.fetchall()]
    
    def delete(self, service: str):
        """Удаляет запись о сервисе из хранилища.

        Args:
            service: Название сервиса, для которого нужно удалить
                сохраненные данные.

        Returns:
            None.
        """
        self.cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
        self.conn.commit()
        print(f"Пароль для {service} удален")
    
    def close(self):
        """Закрывает соединение с базой данных.

        Returns:
            None.
        """
        self.conn.close()

class LogStorage:
    """Простое хранилище логов действий пользователя.

    Записывает события в SQLite-таблицу с временем, типом действия
    и связанным сервисом.
    """
    def __init__(self, log_file='logs.db'):
        """Создает или открывает БД логов.

        Args:
            log_file: Путь к файлу SQLite-БД, в котором будут
                храниться записи логов.

        """
        self.conn = sqlite3.connect(log_file)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                timestamp TEXT,
                action TEXT,
                service TEXT
            )
        ''')
        self.conn.commit()
    
    def log(self, action: str, service: str = ""):
        """Записывает новую строку в таблицу логов.

        Args:
            action: Краткое описание действия (например, 'save_password').
            service: Название сервиса, к которому относится действие,
                либо произвольный тег.

        Returns:
            None.
        """
        self.cursor.execute(
            "INSERT INTO logs (timestamp, action, service) VALUES (?, ?, ?)",
            (datetime.datetime.now().isoformat(), action, service)
        )
        self.conn.commit()
    
    def close(self):
        """Закрывает соединение с БД логов.

        Returns:
            None.
        """
        self.conn.close()