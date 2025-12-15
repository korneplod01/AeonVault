import string
import secrets
import math
import os

class PasswordGenerator:
    """Генератор паролей разных типов.

    Поддерживает генерацию сегментированных, произносимых и
    семантических паролей с логированием операций.
    """
    def __init__(self, logs, base_path='.', word_list_file=None):
        """Инициализирует генератор паролей.

        Args:
            logs: Объект LogStorage или аналогичный, используемый для логирования
                действий генератора. Может быть None, если логирование не требуется.
            base_path: Базовая директория для поиска вспомогательных файлов,
                например, словарей слов.
            word_list_file: Имя файла со списком слов для семантической
                генерации паролей. Если None, используется встроенный список.
        """
        self.logs = logs
        self.base_path = base_path
        self.word_vectors = {}
        
        if word_list_file:
            # Создаем полный путь к файлу слов
            word_list_path = os.path.join(base_path, word_list_file)
            self._load_word_list(word_list_path)


    def _log(self, message, tag='info'):
        """Логирует служебное сообщение, если доступен логгер.

        Args:
            message: Текст сообщения для записи в лог.
            tag: Строковый тег или имя сервиса, по которому можно
                группировать записи (например, 'generator', 'error').
        """
        if self.logs:
            self.logs.log(action=message, service=tag)


    def generate_segmented_password(self, segment_length=6, segments_amount=3, 
                                    separator='-', include_special=False):
        """Генерирует пароль из нескольких сегментов фиксированной длины.

        Каждый сегмент состоит из случайных букв и цифр (и при желании
        специальных символов) и гарантированно содержит хотя бы одну букву.

        Args:
            segment_length: Длина одного сегмента пароля.
            segments_amount: Количество сегментов в пароле.
            separator: Строка-разделитель между сегментами.
            include_special: Если True, добавляет к алфавиту специальные
                символы из string.punctuation.

        Returns:
            str: Сгенерированный пароль вида ``XXXX-YYYY-ZZZZ`` и т.п.
        """
        if include_special:
            charset = string.ascii_letters + string.digits + string.punctuation
        else:
            charset = string.ascii_letters + string.digits
        
        password_parts = []
        for _ in range(segments_amount):
            segment = ''.join(secrets.choice(charset) for _ in range(segment_length))
            
            # Гарантируем наличие хотя бы одной буквы в каждом сегменте
            if not any(c.isalpha() for c in segment):
                pos = secrets.randbelow(segment_length)
                segment = segment[:pos] + secrets.choice(string.ascii_letters) + segment[pos+1:]
            
            password_parts.append(segment)
        
        password = separator.join(password_parts)
        
        self._log(f'Generated segmented password: {segment_length}x{segments_amount} '
                f'with separator "{separator}"', 'generator')
        
        return password


    def generate_readable_password(self, syllable_count=4):
        """Генерирует условно произносимый пароль на основе слогов.

        Пароль строится из чередования согласных и гласных с небольшой
        долей случайности, после чего первая буква делается заглавной
        и в конец добавляется случайная цифра.

        Args:
            syllable_count: Количество слогов (сочетаний букв), используемых
                при формировании основы пароля.

        Returns:
            str: Сгенерированный пароль с хотя бы одной буквой и цифрой в конце.
        """
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        
        password = ''
        for _ in range(syllable_count):
            # Начинаем с согласной (с вероятностью 75%)
            if secrets.choice([True, True, True, False]):
                password += secrets.choice(consonants)
            password += secrets.choice(vowels)
            
            # Добавляем вторую согласную (с вероятностью 50%)
            if secrets.choice([True, False]):
                password += secrets.choice(consonants)
        
        # Делаем первую букву заглавной и добавляем цифру
        password = password.capitalize() + str(secrets.randbelow(10))
        
        self._log(f'Generated readable password with {syllable_count} syllables', 'generator')
        
        return password


    def _load_word_list(self, path):
        """Загружает список слов из указанного файла.

        Если файл отсутствует, используется встроенный набор слов по умолчанию.

        Args:
            path: Путь к текстовому файлу со словами (по одному слову в строке).

        Returns:
            None.
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip()]
            self.word_list = words
            self._log(f'Loaded {len(words)} words from {path}', 'generator')
        except FileNotFoundError:
            self._log(f'Word list file {path} not found, using default', 'generator_error')
            self.word_list = self._get_default_words()


    def _get_default_words(self):
        """Возвращает встроенный список слов по умолчанию.

        Returns:
            list[str]: Список английских слов, используемых для семантической
            генерации паролей, если внешний словарь недоступен.
        """
        return [
            'apple', 'banana', 'car', 'house', 'tree', 'water', 'fire', 'earth', 
            'wind', 'sun', 'moon', 'star', 'book', 'pen', 'road', 'city', 'river',
            'mountain', 'ocean', 'forest', 'garden', 'friend', 'family', 'music',
            'dance', 'light', 'shadow', 'dream', 'hope', 'peace', 'power', 'time',
            'space', 'heart', 'brain', 'hand', 'foot', 'eye', 'ear', 'voice'
        ]


    def _simple_vector(self, word):
        """Создает простое векторное представление слова.

        Представляет слово в виде вектора длиной 26, содержащего
        нормализованные частоты букв латинского алфавита.

        Args:
            word: Исходное слово, для которого строится вектор.

        Returns:
            list[float]: Нормализованный вектор длиной 26.
        """
        vector = [0] * 26
        word = word.lower()
        
        for char in word:
            if 'a' <= char <= 'z':
                char_index = ord(char) - ord('a')
                vector[char_index] += 1
        
        # Нормализуем вектор
        length = math.sqrt(sum(x * x for x in vector))
        if length > 0:
            vector = [x/length for x in vector]
        
        return vector
    

    def _cosine_similarity(self, vec1, vec2):
        """Вычисляет косинусное сходство двух векторов.

        Args:
            vec1: Первый вектор чисел одинаковой длины.
            vec2: Второй вектор чисел одинаковой длины.

        Returns:
            float: Значение косинусного сходства от 0 до 1.
                При несоответствии размеров возвращает 0.
        """
        if len(vec1) != len(vec2): # Защита от ошибок; векторы должны быть длины 1
            return 0
        
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        return dot_product
    

    def _semantic_distance(self, word1, word2):
        """Оценивает семантическую близость двух слов.

        В расчет входят косинусное сходство их векторных представлений,
        разница длин слов и доля общих букв.

        Args:
            word1: Первое слово.
            word2: Второе слово.

        Returns:
            float: Итоговая оценка близости в диапазоне от 0 до 1,
            где большие значения означают большую похожесть.
        """
        vec1 = self._simple_vector(word1)
        vec2 = self._simple_vector(word2)
        
        # Косинусная близость
        similarity = self._cosine_similarity(vec1, vec2)
        
        # Дополнительные факторы
        # 1. Длина слов (чем ближе длина, тем лучше)
        length_factor = 1 - abs(len(word1) - len(word2)) / max(len(word1), len(word2), 1)
        
        # 2. Общие буквы
        common_letters = len(set(word1) & set(word2))
        max_letters = max(len(set(word1)), len(set(word2)), 1)
        common_factor = common_letters / max_letters
        
        # Итоговая оценка
        final_score = (similarity * 0.5 + length_factor * 0.3 + common_factor * 0.2)
        
        return final_score
    

    def generate_semantic_password(self, theme_word=None, password_length=3, 
                                max_similarity=0.7, min_similarity=0.2):
        """Генерирует пароль из семантически связанных слов.

        Выбирает слова, похожие на тематическое по простым
        показателям (частоты букв, длина, общие буквы), применяет
        случайные преобразования регистра и замен букв на цифры,
        а затем объединяет слова случайным разделителем.

        Args:
            theme_word: Тематическое слово, относительно которого подбираются
                остальные. Если None, выбирается случайное слово из словаря.
            password_length: Количество слов, которые нужно включить в пароль.
            max_similarity: Максимально допустимая близость к теме для
                отбираемых слов.
            min_similarity: Минимальная близость слов к теме, ниже которой
                слово не рассматривается.

        Returns:
            tuple[str, str, list[str]]: Кортеж из:
                * сгенерированного пароля,
                * фактически использованной темы,
                * списка выбранных слов.
        """
        if not hasattr(self, 'word_list'):
            self.word_list = self._get_default_words()
        
        if theme_word is None:
            theme_word = secrets.choice(self.word_list)
        
        # Фильтруем слова по длине (исключаем слишком короткие/длинные)
        filtered_words = [word for word in self.word_list if 3 <= len(word) <= 8]
        
        if not filtered_words:
            filtered_words = self.word_list
        
        # Выбираем слова, связанные с темой
        related_words = []
        for word in filtered_words:
            if word.lower() == theme_word.lower():
                continue
            
            similarity = self._semantic_distance(theme_word, word)
            if min_similarity <= similarity <= max_similarity:
                related_words.append((word, similarity))
        
        # Сортируем по близости и берем нужное количество
        related_words.sort(key=lambda x: x[1], reverse=True)
        selected_words = [theme_word]
        
        for word, similarity in related_words:
            if len(selected_words) >= password_length:
                break
            
            # Проверяем, чтобы новое слово не было слишком похоже на уже выбранные
            too_similar = False
            for existing_word in selected_words:
                if self._semantic_distance(existing_word, word) > max_similarity * 1.2:
                    too_similar = True
                    break
            
            if not too_similar:
                selected_words.append(word)
        
        # Если не набрали достаточно слов, добавляем случайные
        while len(selected_words) < password_length:
            random_word = secrets.choice(filtered_words)
            if random_word not in selected_words:
                selected_words.append(random_word)
        
        # Создаем пароль с разделителями и преобразованиями
        password_parts = []
        for word in selected_words:
            if secrets.choice([True, False]):  # 50% шанс изменения регистра
                word = word.capitalize()
            
            if secrets.choice([True, False]):  # 50% шанс заменить буквы на цифры
                replacements = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
                for old, new in replacements.items():
                    if secrets.choice([True, False]):
                        word = word.replace(old, new).replace(old.upper(), new)
            
            password_parts.append(word)
        
        # Выбираем случайный разделитель
        separators = ['-', '_', '.', '', '+', '=']
        separator = secrets.choice(separators)
        
        password = separator.join(password_parts)
        
        # Добавляем цифру в конце с вероятностью 80%
        if secrets.choice([True, True, True, True, False]):
            password += str(secrets.randbelow(10))
        
        if self.logs:
            self._log(f'Generated semantic password based on theme: "{theme_word}"', 'generator')
        
        return password, theme_word, selected_words