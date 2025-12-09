import random
import string
import secrets
import math
from typing import List, Tuple
from storage import LogStorage

class PasswordGenerator:
    def __init__(self, logs, word_list_path=None):
        '''
        Инициализация генератора паролей
        :param logs: объект LogStorage для логирования (опционально)
        :param word_list_path: путь к файлу со словами для генерации со смыслом
        '''
        self.logs = logs
        self.word_vectors = {}
        
        if word_list_path:
            self._load_word_list(word_list_path)


    def _log(self, message, tag='info'):
        '''Вспомогательный метод для логирования'''
        if self.logs:
            self.logs.write_log(message, tag)


    def generate_segmented_password(self, segment_length=6, segments=3, 
                                    separator='-', include_special=False):
            '''
            Генерация пароля с сегментами вида 6-6-6 или подобного
            :param segment_length: длина каждого сегмента
            :param segments: количество сегментов
            :param separator: разделитель между сегментами
            :param include_special: включать ли специальные символы
            :return: сгенерированный пароль
            '''
            if include_special:
                charset = string.ascii_letters + string.digits + string.punctuation
            else:
                charset = string.ascii_letters + string.digits
            
            password_parts = []
            for i in range(segments):
                segment = ''.join(secrets.choice(charset) for _ in range(segment_length))
                
                # Гарантируем наличие хотя бы одной буквы в каждом сегменте
                if not any(c.isalpha() for c in segment):
                    pos = secrets.randbelow(segment_length)
                    segment = segment[:pos] + secrets.choice(string.ascii_letters) + segment[pos+1:]
                
                password_parts.append(segment)
            
            password = separator.join(password_parts)
            
            if self.logs:
                self._log(f'Generated segmented password: {segment_length}x{segments} '
                        f'with separator "{separator}"', 'generator')
            
            return password


    def generate_readable_password(self, syllable_count=4):
            '''Генерация произносимого пароля на основе слогов'''
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'
            
            password = ''
            for i in range(syllable_count):
                # Начинаем с согласной (с вероятностью 75%)
                if secrets.choice([True, True, True, False]):
                    password += secrets.choice(consonants)
                password += secrets.choice(vowels)
                
                # Добавляем вторую согласную (с вероятностью 50%)
                if secrets.choice([True, False]):
                    password += secrets.choice(consonants)
            
            # Делаем первую букву заглавной и добавляем цифру
            password = password.capitalize() + str(secrets.randbelow(10))
            
            if self.logs:
                self._log(f'Generated readable password with {syllable_count} syllables', 'generator')
            
            return password


    def _load_word_list(self, path):
        '''Загрузка списка слов из файла'''
        try:
            with open(path, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip()]
            self.word_list = words
            if self.logs:
                self._log(f'Loaded {len(words)} words from {path}', 'generator')
        except FileNotFoundError:
            if self.logs:
                self._log(f'Word list file {path} not found, using default', 'generator_error')
            self.word_list = self._get_default_words()


    def _get_default_words(self):
        '''Стандартный список слов'''
        return [
            'apple', 'banana', 'car', 'house', 'tree', 'water', 'fire', 'earth', 
            'wind', 'sun', 'moon', 'star', 'book', 'pen', 'road', 'city', 'river',
            'mountain', 'ocean', 'forest', 'garden', 'friend', 'family', 'music',
            'dance', 'light', 'shadow', 'dream', 'hope', 'peace', 'power', 'time',
            'space', 'heart', 'brain', 'hand', 'foot', 'eye', 'ear', 'voice'
        ]


    def _simple_vector(self, word):
        '''Создание простого векторного представления слова'''
        vector = [0] * 26  # для 26 букв английского алфавита
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
        """Вычисление косинусной близости между векторами"""
        if len(vec1) != len(vec2): # Защита от ошибок; векторы должны быть длины 1
            return 0
        
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        return dot_product
    

    def _semantic_distance(self, word1, word2):
        """Вычисление семантической близости слов"""
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
        """
        Генерация пароля из семантически связанных слов
        :param theme_word: тематическое слово (если None - случайная тема)
        :param password_length: количество слов в пароле
        :param max_similarity: максимальная близость к основному слову; по умолчанию
        :param min_similarity: минимальная близость между словами
        :return: пароль из связанных слов
        """
        if not hasattr(self, 'word_list'):
            self.word_list = self._get_default_words()
        
        # Выбираем тематическое слово
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
        for i, word in enumerate(selected_words):
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


logst = LogStorage()
generator = PasswordGenerator(logst)
# 1. Тест сегментированных паролей
print("1. СЕГМЕНТИРОВАННЫЕ ПАРОЛИ:")
print(f"   6-6-6: {generator.generate_segmented_password(6, 3, '-')}")
print(f"   4-4-4-4: {generator.generate_segmented_password(4, 4, '-')}")
print(f"   8-8 (с спецсимволами): {generator.generate_segmented_password(8, 2, '-', True)}")


# 2. Тест произносимых паролей
print("\n3. ПРОИЗНОСИМЫЕ ПАРОЛИ:")
print(f"   4 слога: {generator.generate_readable_password(4)}")
print(f"   6 слогов: {generator.generate_readable_password(6)}")

# 3. Тест семантических паролей
print("\n4. СЕМАНТИЧЕСКИЕ ПАРОЛИ (со смыслом):")

# Создаем тестовый список слов
test_words = [
    "sun", "moon", "star", "sky", "cloud", "rain", "snow", "wind",
    "tree", "flower", "river", "mountain", "ocean", "forest", "earth"
]
generator.word_list = test_words

for theme in ["sun", "tree", "water"]:
    password, main_word, words = generator.generate_semantic_password(
        theme_word=theme, 
        password_length=3
    )
    print(f"   Тема '{theme}': {password}")
    print(f"   Использованные слова: {words}")
