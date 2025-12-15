"""Менеджер паролей, основной файл.

Приложение позволяет сохранять, шифровать и просматривать пароли
для различных сервисов через консольное меню.
"""
import getpass
import os
from storage import PasswordStorage, LogStorage
from generator import PasswordGenerator

def main():
    """Запускает консольный интерфейс менеджера паролей.

    Создает необходимые директории и подключения к БД, инициализирует
    логирование, генератор паролей и хранилище, затем отображает
    главное меню с основными действиями пользователя.
    """
    print("=" * 50)
    print("МЕНЕДЖЕР ПАРОЛЕЙ")
    print("=" * 50)
    
    if not os.path.exists('data'):
        os.makedirs('data')
    
    try:
        logger = LogStorage('data/logs.db')
        
        wordlist_file = "words.txt" if os.path.exists(os.path.join('data', 'words.txt')) else None
        generator = PasswordGenerator(logger, 'data', wordlist_file)
        storage = PasswordStorage('data' + '/passwords.db')
        
        logger.log('app_start', 'system')
        
    except Exception as e:
        print(f"Ошибка инициализации: {e}")
        return
    
    while True:
        print("\nГЛАВНОЕ МЕНЮ")
        print("1. Показать все сервисы")
        print("2. Найти пароль")
        print("3. Сохранить пароль")
        print("4. Удалить пароль")
        print("5. Сгенерировать пароль")
        print("6. Выход")
        
        try:
            choice = input("\nВыберите действие (1-6): ").strip()
            
            if choice == '1':
                # Показать все сервисы
                services = storage.list_all()
                if services:
                    print("\nСохраненные сервисы:")
                    for service in services:
                        print(f"  - {service}")
                else:
                    print("Нет сохраненных паролей")
                logger.log('list_services', 'user')
                
            elif choice == '2':
                # Найти пароль
                service = input("Введите название сервиса: ").strip()
                result = storage.get(service)
                if result:
                    login, password = result
                    print(f"\nДанные для {service}:")
                    print(f"  Логин: {login}")
                    print(f"  Пароль: {password}")
                else:
                    print(f"Сервис '{service}' не найден")
                logger.log('get_password', service)
                
            elif choice == '3':
                # Сохранить пароль
                service = input("Название сервиса: ").strip()
                login = input("Логин: ").strip()
                
                print("\nВарианты ввода пароля:")
                print("1. Ввести вручную")
                print("2. Сгенерировать автоматически")
                pass_choice = input("Выберите (1/2): ").strip()
                
                if pass_choice == '2':
                    print("\nТипы паролей:")
                    print("1. Сегментированный (например, Abc-123-Xyz)")
                    print("2. Произносимый (например, Bano3)")
                    print("3. Семантический (осмысленные слова)")
                    
                    gen_choice = input("Выберите тип (1/3): ").strip()
                    
                    if gen_choice == '1':
                        password = generator.generate_segmented_password()
                    elif gen_choice == '2':
                        password = generator.generate_readable_password()
                    elif gen_choice == '3':
                        password, theme, _ = generator.generate_semantic_password()
                        print(f"Тема пароля: {theme}")
                    else:
                        print("Используется сегментированный пароль по умолчанию")
                        password = generator.generate_segmented_password()
                    
                    print(f"Сгенерированный пароль: {password}")
                else:
                    password = getpass.getpass("Пароль: ")
                
                storage.save(service, login, password)
                print(f"Пароль для '{service}' сохранен")
                logger.log('save_password', service)
                
            elif choice == '4':
                # Удалить пароль
                service = input("Введите название сервиса для удаления: ").strip()
                confirm = input(f"Удалить '{service}'? (да/нет): ").strip().lower()
                if confirm == 'да':
                    storage.delete(service)
                    logger.log('delete_password', service)
                
            elif choice == '5':
                # Генератор паролей
                print("\nГЕНЕРАТОР ПАРОЛЕЙ")
                print("1. Сегментированный (например, Abc-123-Xyz)")
                print("2. Произносимый (например, Pepe0)")
                print("3. Из похожих слов")
                print("4. Назад")
                
                gen_choice = input("Выберите тип (1/4): ").strip()
                
                if gen_choice == '1':
                    length = input("Длина сегмента (по умолчанию 6): ").strip()
                    segments = input("Количество сегментов (по умолчанию 3): ").strip()
                    
                    length = int(length) if length.isdigit() else 6
                    segments = int(segments) if segments.isdigit() else 3
                    
                    password = generator.generate_segmented_password(
                        segment_length=length,
                        segments_amount=segments
                    )
                    print(f"Сгенерированный пароль: {password}")
                    
                elif gen_choice == '2':
                    syllables = input("Количество слогов (по умолчанию 4): ").strip()
                    syllables = int(syllables) if syllables.isdigit() else 4
                    
                    password = generator.generate_readable_password(
                        syllable_count=syllables
                    )
                    print(f"Сгенерированный пароль: {password}")
                    
                elif gen_choice == '3':
                    theme = input("Тематическое слово (Enter для случайной): ").strip()
                    theme = theme if theme else None
                    
                    words_count = input("Количество слов (по умолчанию 3): ").strip()
                    words_count = int(words_count) if words_count.isdigit() else 3
                    
                    password, used_theme, word_list = generator.generate_semantic_password(
                        theme_word=theme,
                        password_length=words_count
                    )
                    print(f"Тема: {used_theme}")
                    print(f"Использованные слова: {', '.join(word_list)}")
                    print(f"Сгенерированный пароль: {password}")
                    
                logger.log('generate_password', 'generator')
                
            elif choice == '6':
                # Выход
                print("Выход из программы...")
                logger.log('app_exit', 'system')
                storage.close()
                logger.close()
                break
                
            else:
                print("Неверный выбор. Попробуйте снова.")
                
        except KeyboardInterrupt:
            print("\n\nВыход из программы...")
            storage.close()
            logger.close()
            break
        except Exception as e:
            print(f"Ошибка: {e}")

if __name__ == "__main__":
    main()