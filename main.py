from rsa_code import TestRSA, ModularArithmetic, Attack, RSAKeyGenerator, FileManager, MessageConverter, RSA, \
    PrimeGenerator
import random
import time
import os
from datetime import datetime

class InteractiveMode:
    """
    Интерактивный режим работы с RSA.

    Функциональность (в соответствии с заданием):
    1. Генерация ключевой пары
    2. Загрузка ключей из файлов
    3. Шифрование текста/файла
    4. Расшифрование текста/файла
    5. Демонстрация атаки
    """

    def __init__(self):
        self.rsa = RSA()
        self.generator = None
        self.keys_loaded = False
        self.current_n_bits = 0

    def run(self):
        """Запуск интерактивного режима."""
        self._show_welcome()

        while True:
            self._show_menu()
            choice = input("\n👉 Ваш выбор: ").strip()

            if choice == '1':
                self._generate_keys()
            elif choice == '2':
                self._load_keys()
            elif choice == '3':
                self._show_keys()
            elif choice == '4':
                self._encrypt_text()
            elif choice == '5':
                self._decrypt_text()
            elif choice == '6':
                self._encrypt_file()
            elif choice == '7':
                self._decrypt_file()
            elif choice == '8':
                self._attack_demo()
            elif choice == '0':
                print("\n👋 До свидания!")
                break
            else:
                print("\n❌ Неверный выбор")

    def _show_welcome(self):
        print("=" * 70)
        print("🔐 RSA КРИПТОСИСТЕМА (ГОСТ Р 34.10-2012)".center(70))
        print("=" * 70)
        print("\n📖 Справка:")
        print("   • Реализован алгоритм RSA с поддержкой больших чисел (до 4096 бит)")
        print("   • Поддерживаются русский и английский текст, эмодзи")
        print("   • Соответствует требованиям практической работы №7")
        print("=" * 70)

    def _show_menu(self):
        print("\n" + "━" * 60)
        print("📋 ГЛАВНОЕ МЕНЮ")
        print("━" * 60)
        print("1. 🔑 Сгенерировать ключевую пару")
        print("2. 📂 Загрузить ключи из файлов")
        print("3. 👁️ Показать текущие ключи")
        print("4. ✏️ Зашифровать текст")
        print("5. 📖 Расшифровать текст")
        print("6. 📁 Зашифровать файл")
        print("7. 📁 Расшифровать файл")
        print("8. 🪓 Демонстрация атаки (для маленького модуля)")
        print("0. 🚪 Выход")
        print("━" * 60)

    def _generate_keys(self):
        """Генерация ключевой пары."""
        print("\n🔑 ГЕНЕРАЦИЯ КЛЮЧЕЙ")
        print("   Доступные размеры: 256, 512, 1024, 2048, 4096 бит")

        bits = input("👉 Размер ключа в битах (2048): ").strip()
        bits = int(bits) if bits else 2048

        self.generator = RSAKeyGenerator(bits=bits)
        public, private = self.generator.generate()
        self.rsa.set_public_key(*public)
        self.rsa.set_private_key(*private)
        self.keys_loaded = True
        self.current_n_bits = public[1].bit_length()

        print(f"\n✅ Открытый ключ: e={public[0]}, n={self.current_n_bits} бит")
        print(f"✅ Закрытый ключ: d={private[0].bit_length()} бит")

        save = input("\nСохранить ключи в файлы? (y/n): ").strip().lower()
        if save == 'y':
            prefix = input("Префикс для файлов (rsa_keys): ").strip() or "rsa_keys"
            self.generator.save_keys_to_files(prefix)

    def _load_keys(self):
        """Загрузка ключей из файлов."""
        print("\n📂 ЗАГРУЗКА КЛЮЧЕЙ")
        pub_file = input("Файл с открытым ключом (rsa_keys_public.txt): ").strip() or "rsa_keys_public.txt"
        priv_file = input("Файл с закрытым ключом (rsa_keys_private.txt): ").strip() or "rsa_keys_private.txt"

        try:
            self.generator = RSAKeyGenerator()
            e, n = self.generator.load_public_key_from_file(pub_file)
            self.rsa.set_public_key(e, n)
            d, n2 = self.generator.load_private_key_from_file(priv_file)
            self.rsa.set_private_key(d, n2)
            self.keys_loaded = True
            self.current_n_bits = n.bit_length()
            print(f"✅ Ключи загружены. n = {self.current_n_bits} бит")
        except Exception as e:
            print(f"❌ Ошибка: {e}")

    def _show_keys(self):
        """Отображение текущих ключей."""
        if not self.keys_loaded:
            print("\n❌ Ключи не загружены и не сгенерированы")
            return

        e, n = self.rsa.public_key
        d, _ = self.rsa.private_key
        print(f"\n📌 Открытый ключ: e={e}\n                 n={n} ({n.bit_length()} бит)")
        print(f"📌 Закрытый ключ: d={d} ({d.bit_length()} бит)")

    def _encrypt_text(self):
        """Шифрование текста (ручной ввод)."""
        if not self.keys_loaded:
            print("\n❌ Сначала сгенерируйте или загрузите ключи")
            return

        print("\n✏️ ШИФРОВАНИЕ ТЕКСТА")
        print("   Введите текст на русском или английском языке:")
        text = input(">>> ").strip()

        if not text:
            print("❌ Текст не может быть пустым")
            return

        # ДО ШИФРОВАНИЯ показываем числовое представление
        show_details = input("\nПоказать числовое представление (ASCII, двоичный вид)? (y/n): ").strip().lower()
        if show_details == 'y':
            block_bits_preview = MessageConverter.get_block_bits(self.rsa.public_key[1])
            MessageConverter.display_numerical_representation(text, block_bits_preview)
        print(f"\n📏 Исходный текст: {len(text)} символов, {len(text.encode('utf-8'))} байт")
        # Выводим символы и их коды
        print(f"\n   Символы: {', '.join(text)}")
        print(f"   ASCII-коды: {', '.join(str(ord(c)) for c in text)}")
        print(f"   HEX: {', '.join(f'0x{ord(c):02X}' for c in text)}")

        # Двоичное представление
        binary_bytes = ' '.join(f'{ord(c):08b}' for c in text)
        print(f"\n   Двоичное представление (побайтово):")
        print(f"      {binary_bytes}")

        full_binary = ''.join(f'{ord(c):08b}' for c in text)
        print(f"   Длина: {len(full_binary)} бит")

        print("⏳ Выполняется шифрование...")

        encrypted, block_bits, original_bit_length = self.rsa.encrypt(text)

        print(f"\n✅ Зашифровано за {self.rsa.encrypt_time:.4f} сек")
        print(f"📌 Количество блоков: {len(encrypted)}")
        print(f"📌 Размер блока: {block_bits} бит")
        print(f"📌 Битовая длина исходного сообщения: {original_bit_length}")
        print(f"📌 Шифротекст: {encrypted}")
        # Вывод шифротекста в формате лекции
        MessageConverter.display_as_lecture(encrypted, block_bits, "Шифротекст")

        # Сохраняем для возможного расшифрования
        self.last_encrypted = encrypted
        self.last_block_bits = block_bits
        self.last_original_bit_length = original_bit_length

        # Показать hex представление
        show_hex = input("\nПоказать HEX-представление шифротекста? (y/n): ").strip().lower()
        if show_hex == 'y':
            hex_repr = ','.join(hex(x) for x in encrypted)
            print(f"   HEX: {hex_repr[:200]}{'...' if len(hex_repr) > 200 else ''}")

        save = input("\nСохранить шифротекст в файл? (y/n): ").strip().lower()
        if save == 'y':
            filename = input("Имя файла (encrypted.txt): ").strip() or "encrypted.txt"
            FileManager.save_encrypted_to_file(encrypted, block_bits, original_bit_length, filename)

    def _decrypt_text(self):
        """Расшифрование текста (ручной ввод)."""
        if not self.keys_loaded or self.rsa.private_key is None:
            print("\n❌ Сначала загрузите или сгенерируйте закрытый ключ")
            return

        print("\n📖 РАСШИФРОВАНИЕ ТЕКСТА")
        print("   Введите зашифрованные блоки через запятую (можно со скобками):")
        cipher = input(">>> ").strip()

        try:
            encrypted = MessageConverter.parse_encrypted_input(cipher)
            block_bits = MessageConverter.get_block_bits(self.rsa.public_key[1])
            print("   Введите битовую длину исходного сообщения (из шага шифрования):")
            original_bit_length = int(input(">>> ").strip())
            decrypted = self.rsa.decrypt(encrypted, block_bits, original_bit_length)
            print(f"\n✅ Расшифрованный текст: {decrypted}")
            print(f"\n   Текст: {decrypted}")
            print(f"   Длина: {len(decrypted)} символов, {len(decrypted.encode('utf-8'))} байт")

            print(f"\n   Символы: {', '.join(decrypted)}")
            print(f"   ASCII-коды: {', '.join(str(ord(c)) for c in decrypted)}")

            # Двоичное представление
            binary_bytes = ' '.join(f'{ord(c):08b}' for c in decrypted)
            print(f"\n   Двоичное представление (побайтово):")
            print(f"      {binary_bytes[:100]}{'...' if len(binary_bytes) > 100 else ''}")

            # Вывод шифротекста, который был расшифрован
            MessageConverter.display_as_lecture(encrypted, block_bits, "Входной шифротекст")

            save = input("\n💾 Сохранить расшифрованный текст в файл? (y/n): ").strip().lower()
            if save == 'y':
                filename = input("   Имя файла (decrypted.txt): ").strip() or "decrypted.txt"
                FileManager.save_text_to_file(decrypted, filename)

        except Exception as e:
            print(f"❌ Ошибка: {e}")

    def _encrypt_file(self):
        """Шифрование файла."""
        if not self.keys_loaded:
            print("\n❌ Сначала сгенерируйте или загрузите ключи")
            return

        print("\n📁 ШИФРОВАНИЕ ФАЙЛА")
        infile = input("Входной файл (plaintext.txt): ").strip() or "plaintext.txt"
        outfile = input("Выходной файл (encrypted.txt): ").strip() or "encrypted.txt"

        try:
            text = FileManager.load_text_from_file(infile)
            encrypted, block_bits, original_bit_length = self.rsa.encrypt(text)
            FileManager.save_encrypted_to_file(encrypted, block_bits, original_bit_length, outfile)
            print(f"✅ Файл зашифрован")
        except Exception as e:
            print(f"❌ Ошибка: {e}")

    def _decrypt_file(self):
        """Расшифрование файла."""
        if not self.keys_loaded or self.rsa.private_key is None:
            print("\n❌ Сначала загрузите или сгенерируйте закрытый ключ")
            return

        print("\n📁 РАСШИФРОВАНИЕ ФАЙЛА")
        infile = input("Входной файл (encrypted.txt): ").strip() or "encrypted.txt"
        outfile = input("Выходной файл (decrypted.txt): ").strip() or "decrypted.txt"

        try:
            encrypted, block_bits, original_bit_length = FileManager.load_encrypted_from_file(infile)
            decrypted = self.rsa.decrypt(encrypted, block_bits, original_bit_length)
            FileManager.save_text_to_file(decrypted, outfile)
            print(f"✅ Файл расшифрован")
            print(f"\n📨 Расшифрованный текст (первые 200 символов):")
            print(decrypted[:200] + "..." if len(decrypted) > 200 else decrypted)
        except Exception as e:
            print(f"❌ Ошибка: {e}")

    def _attack_demo(self):
        """Демонстрация криптоаналитических атак с выбором."""
        print("\n" + "🪓" * 35)
        print("ДЕМОНСТРАЦИЯ КРИПТОАНАЛИТИЧЕСКИХ АТАК")
        print("🪓" * 35)

        print("\nВыберите тип атаки:")
        print("   1. 🔓 Факторизация перебором (для маленьких n)")
        print("   2. 📐 Метод Ферма (когда p и q близки)")
        print("   3. 🔢 Атака Хастада (e=3, маленькое сообщение)")
        print("   4. 🎯 Комбинированная атака (автоматический подбор)")

        choice = input("\n👉 Ваш выбор: ").strip()

        if choice == '1':
            self._attack_bruteforce()
        elif choice == '2':
            self._attack_fermat()
        elif choice == '3':
            self._attack_hastad()
        elif choice == '4':
            self._attack_combined()
        else:
            print("❌ Неверный выбор")

    def _attack_bruteforce(self):
        """Атака 1: Факторизация перебором."""
        print("\n🔓 АТАКА: ФАКТОРИЗАЦИЯ ПЕРЕБОРОМ")
        print("   Генерируем маленький ключ (16 бит)...")

        gen = RSAKeyGenerator(bits=16)
        public, private = gen.generate()
        e, n = public
        d_real, _ = private

        print(f"\n📌 Открытый ключ: e = {e}")
        print(f"                 n = {n} ({n.bit_length()} бит)")
        print(f"📌 Закрытый ключ (секрет): d = {d_real}")

        print("\n⏳ Выполняется атака (факторизация перебором)...")
        import time
        start = time.time()
        p, q = Attack.factorize_bruteforce(n)
        elapsed = time.time() - start

        if p and q:
            phi = (p - 1) * (q - 1)
            d_found = ModularArithmetic.mod_inverse(e, phi)
            print(f"\n✅ АТАКА УСПЕШНА! (время: {elapsed:.4f} сек)")
            print(f"   Найдено: p = {p}, q = {q}")
            print(f"   Проверка: {p} × {q} = {p * q} (должно быть {n})")
            print(f"   φ(n) = {phi}")
            print(f"   Восстановленный d = {d_found}")
            print(f"   Реальный d = {d_real}")
            if d_found == d_real:
                print("   ✅ Ключ восстановлен полностью верно!")
        else:
            print("\n❌ Атака не удалась (n слишком большой для перебора)")

    def _attack_fermat(self):
        """Атака 2: Метод Ферма."""
        print("\n📐 АТАКА: МЕТОД ФЕРМА")
        print("   Генерируем ключ с близкими p и q...")

        # Генерируем близкие p и q
        bits = 16
        p = PrimeGenerator.generate_prime(bits)
        q = p + random.randrange(10, 200)
        while not PrimeGenerator.miller_rabin(q):
            q += 2
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        if ModularArithmetic.gcd(e, phi) != 1:
            e = 17
        d = ModularArithmetic.mod_inverse(e, phi)

        print(f"\n📌 Открытый ключ: e = {e}")
        print(f"                 n = {n} ({n.bit_length()} бит)")
        print(f"📌 Секретные p и q: p = {p}, q = {q}")
        print(f"   Разница между p и q: {abs(p - q)}")

        print("\n⏳ Выполняется атака методом Ферма...")
        import time
        start = time.time()
        p_found, q_found = Attack.factorize_fermat(n)
        elapsed = time.time() - start

        if p_found and q_found and p_found * q_found == n:
            print(f"\n✅ АТАКА УСПЕШНА! (время: {elapsed:.4f} сек)")
            print(f"   Найдено: p = {p_found}, q = {q_found}")
            print(f"   Проверка: {p_found} × {q_found} = {p_found * q_found} (должно быть {n})")
        else:
            print("\n❌ Атака не удалась (p и q не достаточно близки)")

    def _attack_hastad(self):
        """Атака 3: Атака Хастада (e=3)."""
        print("\n🔢 АТАКА: АТАКА ХАСТАДА (e=3)")
        print("   Условие: m³ < n (сообщение маленькое)")

        # Генерируем ключ с e=3
        bits = 128
        while True:
            p = PrimeGenerator.generate_prime(bits)
            q = PrimeGenerator.generate_prime(bits)
            if q == p:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            e = 3
            if ModularArithmetic.gcd(e, phi) == 1:
                break

        d = ModularArithmetic.mod_inverse(e, phi)
        m = 42  # маленькое сообщение
        m_cubed = m ** 3
        c = ModularArithmetic.pow_mod(m, e, n)

        print(f"\n📌 Открытый ключ: e = {e}")
        print(f"                 n = {n} ({n.bit_length()} бит)")
        print(f"📌 Сообщение m = {m}")
        print(f"   m³ = {m_cubed}")
        print(f"📌 Шифротекст c = {c}")

        if m_cubed < n:
            print(f"   ✅ Условие выполнено: m³ = {m_cubed} < n")
        else:
            print(f"   ⚠️ Условие не выполнено: m³ = {m_cubed} > n (атака может не сработать)")

        print("\n⏳ Выполняется атака Хастада (извлечение кубического корня)...")
        m_found = Attack.hastad_attack(c, e=3)

        if m_found:
            print(f"\n✅ АТАКА УСПЕШНА!")
            print(f"   Восстановленное сообщение m = {m_found}")
            print(f"   Реальное сообщение m = {m}")
            if m_found == m:
                print("   ✅ Сообщение восстановлено полностью верно!")
        else:
            print("\n❌ Атака не удалась (кубический корень не извлёкся)")

    def _attack_combined(self):
        """Атака 4: Комбинированная атака."""
        print("\n🎯 КОМБИНИРОВАННАЯ АТАКА")
        print("   Автоматический подбор метода взлома...")

        gen = RSAKeyGenerator(bits=16)
        public, private = gen.generate()
        e, n = public
        d_real, _ = private

        print(f"\n📌 Открытый ключ: e = {e}")
        print(f"                 n = {n} ({n.bit_length()} бит)")
        print(f"📌 Закрытый ключ (секрет): d = {d_real}")

        print("\n⏳ Выполняется комбинированная атака...")
        import time
        start = time.time()
        d_found, p_found, q_found = Attack.break_rsa(e, n)
        elapsed = time.time() - start

        if d_found:
            print(f"\n✅ АТАКА УСПЕШНА! (время: {elapsed:.4f} сек)")
            print(f"   Найдено: p = {p_found}, q = {q_found}")
            print(f"   Восстановленный d = {d_found}")
            print(f"   Реальный d = {d_real}")
            if d_found == d_real:
                print("   ✅ Ключ восстановлен полностью верно!")
        else:
            print("\n❌ Атака не удалась (ни один метод не сработал)")


# ============================================================
# 10. ТОЧКА ВХОДА
# ============================================================
if __name__ == "__main__":
    # Запуск автоматических тестов (как в вашем примере отчёта)
    print("\n🔧 ИНИЦИАЛИЗАЦИЯ...")
    TestRSA.run_all()

    # Запуск интерактивного режима
    app = InteractiveMode()
    app.run()