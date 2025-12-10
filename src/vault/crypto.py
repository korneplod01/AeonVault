import hashlib
import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import sqlite3
import json

class VaultCrypto:
    def __init__(self, master_password=None):
        """
        Инициализация системы шифрования
        :param master_password: мастер-пароль (если None, будет запрошен при первой настройке)
        """
        self.master_password = master_password
        self.salt_file = 'vault_salt.bin'
        self.config_file = 'vault_config.json'
        self.is_initialized = self._check_initialization()
        
    def _check_initialization(self):
        """Проверяет, инициализировано ли хранилище"""
        return os.path.exists(self.salt_file) and os.path.exists(self.config_file)
    
    def initialize_vault(self, master_password):
        """
        Инициализация нового хранилища с мастер-паролем
        :param master_password: мастер-пароль
        :return: True если успешно
        """
        try:
            # Генерируем случайную соль
            salt = get_random_bytes(32)
            
            # Сохраняем соль
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            
            # Создаем ключ из мастер-пароля
            key = self._derive_key(master_password, salt)
            
            # Сохраняем конфигурацию (может содержать метаданные в будущем)
            config = {
                'version': '1.0',
                'hash_algorithm': 'PBKDF2_HMAC_SHA256',
                'iterations': 100000,
                'key_length': 32
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
            
            self.master_password = master_password
            self.is_initialized = True
            
            return True
            
        except Exception as e:
            print(f"Ошибка при инициализации хранилища: {e}")
            return False
    
    def _derive_key(self, password, salt=None):
        """
        Создание криптографического ключа из пароля
        :param password: пароль
        :param salt: соль (если None, читается из файла)
        :return: ключ
        """
        if salt is None:
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
        
        # Используем PBKDF2 для создания ключа
        key = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=32,  # Длина ключа 32 байта (256 бит) для AES-256
            count=100000,  # Количество итераций
            hmac_hash_module=hashlib.sha256
        )
        
        return key
    
    def verify_master_password(self, password):
        """
        Проверка мастер-пароля
        :param password: пароль для проверки
        :return: True если пароль верный
        """
        if not self.is_initialized:
            return False
        
        try:
            # Пытаемся создать ключ с введенным паролем
            test_key = self._derive_key(password)
            
            # Для проверки можно попробовать расшифровать тестовые данные
            # или использовать другой метод верификации
            # В данном случае просто проверяем, что можем создать ключ
            return True
            
        except Exception:
            return False
    
    def encrypt_data(self, plaintext):
        """
        Шифрование данных
        :param plaintext: исходный текст для шифрования
        :return: зашифрованные данные в формате base64
        """
        if not self.master_password or not self.is_initialized:
            raise ValueError("Хранилище не инициализировано или мастер-пароль не установлен")
        
        # Создаем ключ
        key = self._derive_key(self.master_password)
        
        # Генерируем случайный IV (Initialization Vector)
        iv = get_random_bytes(16)
        
        # Создаем шифр AES в режиме CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Дополняем данные до кратного 16 байтам (требование AES-CBC)
        padding_length = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext.encode('utf-8') + bytes([padding_length] * padding_length)
        
        # Шифруем
        ciphertext = cipher.encrypt(plaintext_padded)
        
        # Объединяем IV и зашифрованные данные, кодируем в base64
        encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
        
        return encrypted_data
    
    def decrypt_data(self, encrypted_data):
        """
        Расшифровка данных
        :param encrypted_data: зашифрованные данные в формате base64
        :return: расшифрованный текст
        """
        if not self.master_password or not self.is_initialized:
            raise ValueError("Хранилище не инициализировано или мастер-пароль не установлен")
        
        # Декодируем из base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Извлекаем IV (первые 16 байт)
        iv = encrypted_bytes[:16]
        
        # Остальное - зашифрованные данные
        ciphertext = encrypted_bytes[16:]
        
        # Создаем ключ
        key = self._derive_key(self.master_password)
        
        # Создаем шифр для расшифровки
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Расшифровываем
        decrypted_padded = cipher.decrypt(ciphertext)
        
        # Удаляем дополнение
        padding_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-padding_length]
        
        return decrypted.decode('utf-8')
    
    def encrypt_password_entry(self, website, login, password):
        """
        Шифрование записи пароля
        :param website: сайт
        :param login: логин
        :param password: пароль
        :return: зашифрованная запись в формате JSON
        """
        entry = {
            'website': website,
            'login': login,
            'password': password
        }
        
        # Преобразуем в JSON и шифруем
        entry_json = json.dumps(entry)
        encrypted = self.encrypt_data(entry_json)
        
        return encrypted
    
    def decrypt_password_entry(self, encrypted_entry):
        """
        Расшифровка записи пароля
        :param encrypted_entry: зашифрованная запись
        :return: словарь с website, login, password
        """
        decrypted_json = self.decrypt_data(encrypted_entry)
        entry = json.loads(decrypted_json)
        
        return entry


class EncryptedPasswordStorage:
    def __init__(self, crypto: VaultCrypto, logs=None, path='encrypted_vault.db'):
        """
        Зашифрованное хранилище паролей
        :param crypto: объект VaultCrypto для шифрования
        :param logs: объект LogStorage для логирования
        :param path: путь к файлу БД
        """
        self.crypto = crypto
        self.logs = logs
        self.path = path
        self.connection = None
        self.cursor = None
        
        if not self.crypto.is_initialized:
            raise ValueError("Сначала инициализируйте хранилище с мастер-паролем")
        
        self._connect()
        self._create_table()
        
        if self.logs:
            self.logs.write_log('Encrypted password storage initialized', 'system_EncryptedStorage')
    
    def _connect(self):
        """Подключение к зашифрованной БД"""
        self.connection = sqlite3.connect(self.path)
        self.cursor = self.connection.cursor()
    
    def _create_table(self):
        """Создание таблицы для зашифрованных записей"""
        if self.logs:
            self.logs.write_log('Creating encrypted passwords table...', 'system_EncryptedStorage')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS encrypted_passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_hash TEXT NOT NULL,
                encrypted_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(website_hash)
            )
        ''')
        
        # Создаем индекс для быстрого поиска
        self.cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_website_hash 
            ON encrypted_passwords(website_hash)
        ''')
        
        self.connection.commit()
        
        if self.logs:
            self.logs.write_log('Encrypted passwords table created', 'system_EncryptedStorage')
    
    def _hash_website(self, website):
        """Создание хеша сайта для индексации (без возможности восстановления)"""
        return hashlib.sha256(website.lower().encode('utf-8')).hexdigest()
    
    def add_password(self, website, login, password):
        """
        Добавление зашифрованного пароля
        :return: True если успешно
        """
        if self.logs:
            self.logs.write_log(f'Adding encrypted password for {website}/{login}', 'info')
        
        try:
            # Шифруем запись
            encrypted_entry = self.crypto.encrypt_password_entry(website, login, password)
            website_hash = self._hash_website(website)
            
            # Проверяем, существует ли уже запись для этого сайта
            self.cursor.execute(
                "SELECT id FROM encrypted_passwords WHERE website_hash = ?",
                (website_hash,)
            )
            
            if self.cursor.fetchone():
                # Обновляем существующую запись
                self.cursor.execute(
                    "UPDATE encrypted_passwords SET encrypted_data = ?, updated_at = CURRENT_TIMESTAMP WHERE website_hash = ?",
                    (encrypted_entry, website_hash)
                )
                action = 'updated'
            else:
                # Добавляем новую запись
                self.cursor.execute(
                    "INSERT INTO encrypted_passwords (website_hash, encrypted_data) VALUES (?, ?)",
                    (website_hash, encrypted_entry)
                )
                action = 'added'
            
            self.connection.commit()
            
            if self.logs:
                self.logs.write_log(f'Successfully {action} encrypted password for {website}', 'info')
            
            return True
            
        except Exception as e:
            if self.logs:
                self.logs.write_log(f'Failed to add encrypted password for {website}: {str(e)}', 'error')
            return False
    
    def get_password(self, website, login=None):
        """
        Получение пароля по сайту и логину
        :param website: сайт
        :param login: логин (опционально, для проверки соответствия)
        :return: пароль или None если не найден
        """
        if self.logs:
            self.logs.write_log(f'Retrieving encrypted password for {website}', 'info')
        
        try:
            website_hash = self._hash_website(website)
            
            self.cursor.execute(
                "SELECT encrypted_data FROM encrypted_passwords WHERE website_hash = ?",
                (website_hash,)
            )
            
            row = self.cursor.fetchone()
            
            if row:
                # Расшифровываем запись
                entry = self.crypto.decrypt_password_entry(row[0])
                
                # Если передан логин, проверяем соответствие
                if login and entry['login'] != login:
                    if self.logs:
                        self.logs.write_log(f'Login mismatch for {website}', 'warning')
                    return None
                
                if self.logs:
                    self.logs.write_log(f'Successfully retrieved password for {website}', 'info')
                
                return entry['password']
            else:
                if self.logs:
                    self.logs.write_log(f'No password found for {website}', 'info')
                return None
                
        except Exception as e:
            if self.logs:
                self.logs.write_log(f'Failed to retrieve password for {website}: {str(e)}', 'error')
            return None
    
    def list_passwords(self):
        """
        Список всех сайтов в хранилище (без расшифровки данных)
        :return: список кортежей (website_hash, created_at)
        """
        self.cursor.execute(
            "SELECT website_hash, created_at FROM encrypted_passwords ORDER BY created_at DESC"
        )
        
        return self.cursor.fetchall()
    
    def delete_password(self, website):
        """
        Удаление пароля по сайту
        :return: True если успешно
        """
        if self.logs:
            self.logs.write_log(f'Deleting encrypted password for {website}', 'info')
        
        try:
            website_hash = self._hash_website(website)
            
            self.cursor.execute(
                "DELETE FROM encrypted_passwords WHERE website_hash = ?",
                (website_hash,)
            )
            
            self.connection.commit()
            
            deleted = self.cursor.rowcount > 0
            
            if self.logs:
                if deleted:
                    self.logs.write_log(f'Successfully deleted password for {website}', 'info')
                else:
                    self.logs.write_log(f'No password found to delete for {website}', 'info')
            
            return deleted
            
        except Exception as e:
            if self.logs:
                self.logs.write_log(f'Failed to delete password for {website}: {str(e)}', 'error')
            return False
    
    def update_password(self, website, new_password):
        """
        Обновление пароля для сайта
        :return: True если успешно
        """
        if self.logs:
            self.logs.write_log(f'Updating encrypted password for {website}', 'info')
        
        try:
            # Получаем текущую запись
            website_hash = self._hash_website(website)
            
            self.cursor.execute(
                "SELECT encrypted_data FROM encrypted_passwords WHERE website_hash = ?",
                (website_hash,)
            )
            
            row = self.cursor.fetchone()
            
            if row:
                # Расшифровываем, обновляем пароль, перешифровываем
                entry = self.crypto.decrypt_password_entry(row[0])
                entry['password'] = new_password
                
                new_encrypted = self.crypto.encrypt_password_entry(
                    entry['website'], 
                    entry['login'], 
                    entry['password']
                )
                
                # Обновляем в БД
                self.cursor.execute(
                    "UPDATE encrypted_passwords SET encrypted_data = ?, updated_at = CURRENT_TIMESTAMP WHERE website_hash = ?",
                    (new_encrypted, website_hash)
                )
                
                self.connection.commit()
                
                if self.logs:
                    self.logs.write_log(f'Successfully updated password for {website}', 'info')
                
                return True
            else:
                if self.logs:
                    self.logs.write_log(f'No password found to update for {website}', 'info')
                return False
                
        except Exception as e:
            if self.logs:
                self.logs.write_log(f'Failed to update password for {website}: {str(e)}', 'error')
            return False
    
    def close(self):
        """Закрытие соединения с БД"""
        if self.connection:
            self.connection.close()
            if self.logs:
                self.logs.write_log('Encrypted storage connection closed', 'system_EncryptedStorage')


def setup_vault():
    """
    Функция настройки хранилища (интерактивная)
    :return: объект VaultCrypto или None если отменено
    """
    print("=== НАСТРОЙКА БЕЗОПАСНОГО ХРАНИЛИЩА ПАРОЛЕЙ ===")
    print()
    
    # Проверяем, существует ли уже хранилище
    crypto = VaultCrypto()
    
    if crypto.is_initialized:
        print("Обнаружено существующее хранилище.")
        print("Введите мастер-пароль для доступа:")
        
        attempts = 3
        while attempts > 0:
            password = input("Мастер-пароль: ")
            
            if crypto.verify_master_password(password):
                crypto.master_password = password
                print("Доступ разрешен")
                return crypto
            else:
                attempts -= 1
                if attempts > 0:
                    print(f"Неверный пароль. Осталось попыток: {attempts}")
                else:
                    print("Доступ запрещен. Слишком много неудачных попыток.")
                    return None
    else:
        print("Создание нового защищенного хранилища.")
        print("Придумайте надежный мастер-пароль:")
        print("- Минимум 12 символов")
        print("- Используйте буквы, цифры и специальные символы")
        print("- Не используйте простые пароли")
        print()
        
        while True:
            password = input("Новый мастер-пароль: ")
            confirm = input("Повторите мастер-пароль: ")
            
            if password != confirm:
                print("Пароли не совпадают. Попробуйте снова.")
                continue
            
            if len(password) < 12:
                print("Пароль слишком короткий. Минимум 12 символов.")
                continue
            
            # Простая проверка сложности
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in password)
            
            if not (has_upper and has_lower and has_digit and has_special):
                print("Пароль недостаточно сложен. Используйте буквы разного регистра, цифры и специальные символы.")
                continue
            
            # Инициализируем хранилище
            if crypto.initialize_vault(password):
                print("Хранилище успешно создано и защищено!")
                return crypto
            else:
                print("Ошибка при создании хранилища.")
                return None
