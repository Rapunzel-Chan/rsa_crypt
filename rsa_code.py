"""
Программная реализация асимметричной криптосистемы RSA.
Студент: Осина К.В.
Группа: МКБ251
Дисциплина: Криптографические методы защиты информации
Преподаватель: Евсютин О.О.

В соответствии с ГОСТ Р 34.10-2012 (аналоги RSA) и заданием ПР7.
Реализовано без использования готовых библиотечных функций шифрования.
"""

import random
import time
import os
from datetime import datetime


# ============================================================
# 1. МОДУЛЬНАЯ АРИФМЕТИКА
# ============================================================
class ModularArithmetic:
    """
    Класс для операций по модулю.
    Реализует базовые алгоритмы теории чисел.
    """

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """
        Алгоритм Евклида для нахождения наибольшего общего делителя.

        Формула: НОД(a, b) = НОД(b, a mod b)
        """
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a: int, b: int) -> tuple:
        """
        Расширенный алгоритм Евклида.

        Возвращает: (d, x, y) такие, что a*x + b*y = d = НОД(a, b)

        Алгоритм (пошагово):
        1. Инициализируем коэффициенты: x2=1, x1=0, y2=0, y1=1
        2. Пока b > 0:
           q = a // b
           r = a - q*b
           x = x2 - q*x1
           y = y2 - q*y1
           a = b, b = r
           x2 = x1, x1 = x
           y2 = y1, y1 = y
        3. Возвращаем (a, x2, y2)
        """
        x2, x1 = 1, 0
        y2, y1 = 0, 1
        while b:
            q = a // b
            r = a - q * b
            x = x2 - q * x1
            y = y2 - q * y1
            a, b = b, r
            x2, x1 = x1, x
            y2, y1 = y1, y
        return a, x2, y2

    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """
        Нахождение обратного элемента по модулю m.

        Формула: a * a^(-1) ≡ 1 (mod m)

        Шаги:
        1. Вычисляем НОД(a, m) через расширенный алгоритм Евклида
        2. Если НОД ≠ 1, то обратный элемент не существует
        3. Иначе возвращаем x mod m
        """
        d, x, _ = ModularArithmetic.extended_gcd(a, m)
        if d != 1:
            raise ValueError(f"Обратный элемент не существует: НОД({a},{m})={d}")
        return x % m

    @staticmethod
    def pow_mod(base: int, exp: int, mod: int) -> int:
        """
        Быстрое возведение в степень по модулю (бинарный метод).

        Алгоритм (пошагово):
        1. result = 1
        2. base = base mod mod
        3. Пока exp > 0:
           - Если младший бит exp = 1: result = (result * base) mod mod
           - base = (base * base) mod mod
           - exp = exp >> 1 (сдвиг вправо, деление на 2)
        4. Возвращаем result

        Сложность: O(log exp) умножений.
        """
        result = 1
        base = base % mod
        while exp > 0:
            if exp & 1:  # проверяем младший бит
                result = (result * base) % mod
            base = (base * base) % mod
            exp >>= 1  # сдвиг вправо (деление на 2)
        return result

    @staticmethod
    def isqrt(n: int) -> int:
        """
        Целочисленный квадратный корень (метод Ньютона/бинарный поиск).

        Формула: x_{k+1} = (x_k + n/x_k) // 2
        """
        if n < 0:
            raise ValueError("Квадратный корень из отрицательного числа")
        if n == 0:
            return 0
        x = n
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + n // x) // 2
        return x


# ============================================================
# 2. ГЕНЕРАЦИЯ ПРОСТЫХ ЧИСЕЛ (ТЕСТ МИЛЛЕРА-РАБИНА)
# ============================================================
class PrimeGenerator:
    """
    Генерация простых чисел с использованием теста Миллера-Рабина.

    Тест Миллера-Рабина (вероятностный):
    - Вероятность ошибки: 2^{-k}, где k — количество раундов
    - Для k=10 вероятность ошибки < 0.1%
    """

    # Малые простые числа для быстрой предварительной проверки
    SMALL_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

    @staticmethod
    def _check_small_divisors(n: int) -> bool:
        """
        Быстрая проверка на делимость малыми простыми числами.

        Алгоритм:
        1. Если чётное — проверяем, равно ли 2
        2. Для каждого малого простого p:
           - Если n % p == 0, то n простое только если n == p
        """
        if n % 2 == 0:
            return n == 2
        for p in PrimeGenerator.SMALL_PRIMES:
            if n % p == 0:
                return n == p
        return True  # дальше проверяем тестом Миллера-Рабина

    @staticmethod
    def miller_rabin(n: int, k: int = 10) -> bool:
        """
        Тест Миллера-Рабина для проверки простоты числа.

        Алгоритм (пошагово):
        1. Если n < 2: вернуть False
        2. Если n ∈ {2, 3}: вернуть True
        3. Если n чётное: вернуть False (n=2 уже обработано)
        4. Представить n-1 = 2^s * t, где t — нечётное
        5. Для i = 1..k:
           a = случайное число из [2, n-2]
           x = a^t mod n
           Если x = 1 или x = n-1: перейти к следующему a
           Для j = 1..s-1:
               x = x^2 mod n
               Если x = n-1: перейти к следующему a
           Если ни разу не получили n-1: вернуть False (n составное)
        6. Вернуть True (n вероятно простое)

        Математическая основа: малая теорема Ферма.
        """
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False

        # Быстрая проверка малыми делителями
        if not PrimeGenerator._check_small_divisors(n):
            return False

        # Шаг 4: представляем n-1 = 2^s * t
        s, t = 0, n - 1
        while t % 2 == 0:
            s += 1
            t //= 2

        # Шаг 5: k раундов
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = ModularArithmetic.pow_mod(a, t, n)
            if x == 1 or x == n - 1:
                continue

            for _ in range(s - 1):
                x = (x * x) % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_prime(bits: int) -> int:
        """
        Генерация простого числа заданной битовой длины.

        Алгоритм:
        1. Случайно генерируем нечётное число нужной длины
        2. Проверяем на простоту тестом Миллера-Рабина
        3. Если составное — повторяем

        Вероятность успеха: ~1/ln(n) для случайных чисел.
        """
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1  # старший бит = 1, число нечётное
            if PrimeGenerator.miller_rabin(num):
                return num


# ============================================================
# 3. ПРЕОБРАЗОВАТЕЛЬ СООБЩЕНИЙ (ТЕКСТ ↔ ЧИСЛА)
# ============================================================
class MessageConverter:
    """
    Преобразование текста в числа и обратно для шифрования RSA.

    Принцип (как в лекции на стр. 19-20):
    1. Текст → ASCII/UTF-8 коды → двоичная строка
    2. Двоичная строка разбивается на блоки заданной длины
    3. Каждый блок преобразуется в число (int)

    Важно: сохраняется исходная длина битовой строки для корректного удаления паддинга.
    """

    @staticmethod
    def text_to_blocks(text: str, max_value: int) -> tuple:
        """
        Преобразование текста в блоки чисел.

        Вход: text — строка, max_value — модуль n
        Выход: (blocks, block_bits, original_bit_length)

        Шаги:
        1. Кодируем текст в UTF-8
        2. Переводим байты в двоичную строку
        3. Запоминаем исходную длину битовой строки
        4. Разбиваем на блоки по (bit_length(n)-1) бит
        5. Последний блок дополняем нулями до нужной длины
        """
        max_bits = max_value.bit_length() - 1  # блок должен быть меньше n
        if max_bits < 8:
            max_bits = 8

        byte_data = text.encode('utf-8')
        bits = ''.join(f'{b:08b}' for b in byte_data)
        original_bit_length = len(bits)  # <--- ЗАПОМИНАЕМ! (для удаления паддинга)

        blocks = []
        for i in range(0, len(bits), max_bits):
            block_bits = bits[i:i + max_bits]
            if len(block_bits) < max_bits:
                block_bits = block_bits.ljust(max_bits, '0')  # дополняем нулями
            blocks.append(int(block_bits, 2))

        return blocks, max_bits, original_bit_length

    @staticmethod
    def blocks_to_text(blocks: list, block_bits: int, original_bit_length: int) -> str:
        """
        Преобразование блоков чисел обратно в текст.

        Шаги:
        1. Переводим каждый блок в двоичную строку заданной длины
        2. Собираем все биты в одну строку
        3. Обрезаем до исходной длины (удаляем добавленные нули!)
        4. Добиваем до кратности 8 (байты)
        5. Преобразуем в байты и декодируем в UTF-8

        Ключевой момент: использование original_bit_length позволяет
        удалить лишние нулевые байты, которые добавлялись при дополнении.
        Это соответствует подходу из лекции (стр. 19-20).
        """
        all_bits = ''
        for m in blocks:
            all_bits += f'{m:0{block_bits}b}'

        # УДАЛЯЕМ ЛИШНИЕ НУЛИ (дополнение последнего блока)
        all_bits = all_bits[:original_bit_length]

        if not all_bits:
            return ""

        # Добиваем до кратности 8 (байты)
        if len(all_bits) % 8 != 0:
            padding = 8 - (len(all_bits) % 8)
            all_bits = all_bits + '0' * padding

        try:
            byte_data = int(all_bits, 2).to_bytes(len(all_bits) // 8, 'big')
            return byte_data.decode('utf-8')
        except:
            return "[Ошибка декодирования]"

    @staticmethod
    def get_block_bits(max_value: int) -> int:
        """Возвращает оптимальное количество бит на блок."""
        return max_value.bit_length() - 1

    @staticmethod
    def parse_encrypted_input(user_input: str) -> list:
        """
        Парсит ввод пользователя для шифротекста.

        Поддерживает форматы:
        - "123,456,789"
        - "[123,456,789]"
        - "123 456 789"
        """
        user_input = user_input.strip()
        if user_input.startswith('[') and user_input.endswith(']'):
            user_input = user_input[1:-1]
        # Разделяем по запятой, пробелу или табуляции
        import re
        numbers = re.split(r'[,\s]+', user_input)
        return [int(x.strip()) for x in numbers if x.strip()]


    @staticmethod
    def display_numerical_representation(text: str, block_bits: int = None):
        """Вывод числового представления текста (ASCII, двоичный, блоки)."""
        print("\n📊 ЧИСЛОВОЕ ПРЕДСТАВЛЕНИЕ СООБЩЕНИЯ")
        print("-" * 60)

        # ASCII коды
        ascii_codes = [ord(c) for c in text]
        print(f"   ASCII коды: {ascii_codes}")

        # Двоичное представление
        binary_str = ''.join(f'{ord(c):08b}' for c in text)
        print(f"   Двоичная строка: {binary_str[:50]}{'...' if len(binary_str) > 50 else ''}")
        print(f"   Длина двоичной строки: {len(binary_str)} бит")

        # Блоки (если известен размер)
        if block_bits:
            blocks = []
            for i in range(0, len(binary_str), block_bits):
                block = binary_str[i:i + block_bits]
                if len(block) < block_bits:
                    block = block.ljust(block_bits, '0')
                blocks.append((block, int(block, 2)))
            print(f"\n   Разбиение на блоки по {block_bits} бит:")
            for i, (bits, val) in enumerate(blocks, 1):
                print(f"      Блок {i}: {bits} = {val}")


    @staticmethod
    def display_as_lecture(encrypted_blocks, block_bits, title="Шифротекст", show_all=True):
        """
        Вывод шифротекста в формате, аналогичном лекции (стр. 20).

        Параметры:
            encrypted_blocks: список зашифрованных блоков (чисел)
            block_bits: размер блока в битах
            title: заголовок вывода
            show_all: показывать все блоки или только первые 5
        """
        print(f"\n📖 {title} (в формате лекции, стр. 20)")
        print("-" * 50)

        total_blocks = len(encrypted_blocks)
        show_blocks = min(total_blocks, 5) if not show_all else total_blocks

        # 1. Вывод блоков
        print(f"\n   {title} (блоки):")
        for i in range(show_blocks):
            print(f"      c{i + 1} = {encrypted_blocks[i]}")

        if total_blocks > show_blocks:
            print(f"      ... и ещё {total_blocks - show_blocks} блоков")

        # 2. Сборка двоичной строки
        all_bits = ''
        for c in encrypted_blocks[:show_blocks]:
            all_bits += f'{c:0{block_bits}b}'

        if total_blocks > show_blocks:
            all_bits += "..."

        print(f"\n   Двоичная строка (первые {show_blocks} блоков): {all_bits}")

        # 3. Разбивка на байты и ASCII коды
        full_bits = ''
        for c in encrypted_blocks:
            full_bits += f'{c:0{block_bits}b}'

        ascii_codes = []
        for i in range(0, len(full_bits), 8):
            if i + 8 <= len(full_bits):
                byte_bits = full_bits[i:i + 8]
                byte_val = int(byte_bits, 2)
                ascii_codes.append(byte_val)

        # Выводим первые 10 байт
        print(f"\n   ASCII-коды (байты):")
        hex_values = [f"0x{byte:02X}" for byte in ascii_codes[:10]]
        print(f"      {', '.join(hex_values)}")
        if len(ascii_codes) > 10:
            print(f"      ... и ещё {len(ascii_codes) - 10} байт")

        # 4. Символы
        print(f"\n   Символы:")
        chars = []
        for byte_val in ascii_codes[:10]:
            if 32 <= byte_val <= 126:  # печатные ASCII
                chars.append(chr(byte_val))
            elif byte_val == 0:
                chars.append('□')  # нулевой символ
            else:
                chars.append(f'\\x{byte_val:02X}')

        print(f"      {''.join(chars)}")
        if len(ascii_codes) > 10:
            print(f"      ... и ещё {len(ascii_codes) - 10} символов")

        # 5. Общая информация
        print(f"\n   📊 Статистика:")
        print(f"      Всего блоков: {total_blocks}")
        print(f"      Размер блока: {block_bits} бит")
        print(f"      Всего байт: {len(ascii_codes)}")


# ============================================================
# 4. ГЕНЕРАТОР КЛЮЧЕЙ RSA
# ============================================================
class RSAKeyGenerator:
    """
    Генерация пары ключей RSA.

    Алгоритм (пошагово):
    1. Выбираем два простых числа p и q
    2. Вычисляем n = p * q
    3. Вычисляем φ(n) = (p-1)(q-1)
    4. Выбираем e (экспонента зашифрования) так, чтобы НОД(e, φ(n)) = 1
    5. Вычисляем d = e^(-1) mod φ(n) (расширенный алгоритм Евклида)
    6. Пара (e, n) — открытый ключ, (d, n) — закрытый ключ
    """

    def __init__(self, bits: int = 2048):
        self.bits = bits
        self.public_key = None
        self.private_key = None
        self.p = None
        self.q = None
        self.generation_time = None

    def generate(self) -> tuple:
        """Генерация ключевой пары."""
        start_time = time.time()

        print(f"[*] Генерация двух простых чисел по {self.bits} бит...")
        p = PrimeGenerator.generate_prime(self.bits)
        print(f"[+] p сгенерировано ({p.bit_length()} бит)")

        q = PrimeGenerator.generate_prime(self.bits)
        while q == p:
            q = PrimeGenerator.generate_prime(self.bits)
        print(f"[+] q сгенерировано ({q.bit_length()} бит)")

        print("[*] Вычисление n = p * q...")
        n = p * q
        print(f"[+] n = {n.bit_length()} бит")

        print("[*] Вычисление φ(n) = (p-1)*(q-1)...")
        phi = (p - 1) * (q - 1)

        print("[*] Выбор экспоненты e...")
        e = 65537  # наиболее распространённое значение
        if ModularArithmetic.gcd(e, phi) != 1:
            e = 17
            if ModularArithmetic.gcd(e, phi) != 1:
                e = 3
                while ModularArithmetic.gcd(e, phi) != 1:
                    e += 2
        print(f"[+] e = {e}")

        print("[*] Вычисление d = e^(-1) mod φ(n)...")
        d = ModularArithmetic.mod_inverse(e, phi)

        self.public_key = (e, n)
        self.private_key = (d, n)
        self.p = p
        self.q = q
        self.generation_time = time.time() - start_time

        return self.public_key, self.private_key

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key

    def get_p(self):
        return self.p

    def get_q(self):
        return self.q

    def save_keys_to_files(self, filename_prefix: str = "rsa_keys"):
        """Сохраняет ключи в текстовые файлы."""
        if self.public_key is None or self.private_key is None:
            raise ValueError("Ключи не сгенерированы")

        e, n = self.public_key
        d, _ = self.private_key

        with open(f"{filename_prefix}_public.txt", 'w', encoding='utf-8') as f:
            f.write(f"# RSA PUBLIC KEY\n")
            f.write(f"# Created: {datetime.now()}\n")
            f.write(f"# Key size: {self.bits} bits\n")
            f.write(f"{e}\n{n}\n")

        with open(f"{filename_prefix}_private.txt", 'w', encoding='utf-8') as f:
            f.write(f"# RSA PRIVATE KEY\n")
            f.write(f"# Created: {datetime.now()}\n")
            f.write(f"# Key size: {self.bits} bits\n")
            f.write(f"{d}\n{n}\n")

        print(f"[+] Ключи сохранены в {filename_prefix}_public.txt и {filename_prefix}_private.txt")

    def load_public_key_from_file(self, filename: str):
        """Загружает открытый ключ из файла."""
        with open(filename, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        self.public_key = (int(lines[0]), int(lines[1]))
        return self.public_key

    def load_private_key_from_file(self, filename: str):
        """Загружает закрытый ключ из файла."""
        with open(filename, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        self.private_key = (int(lines[0]), int(lines[1]))
        return self.private_key


# ============================================================
# 5. ОСНОВНОЙ КЛАСС RSA (ШИФРОВАНИЕ И РАСШИФРОВАНИЕ)
# ============================================================
class RSA:
    """
    Реализация алгоритма RSA.

    Формулы:
    - Шифрование: c = m^e mod n
    - Расшифрование: m = c^d mod n

    Доказательство корректности (Эйлер):
    Если НОД(m, n) = 1, то m^φ(n) ≡ 1 (mod n)
    Тогда m^(ed) = m^(1 + k·φ(n)) = m·(m^φ(n))^k ≡ m (mod n)
    """

    def __init__(self, public_key=None, private_key=None):
        self.public_key = public_key  # (e, n)
        self.private_key = private_key  # (d, n)
        self.encrypt_time = None
        self.decrypt_time = None

    def set_public_key(self, e: int, n: int):
        self.public_key = (e, n)

    def set_private_key(self, d: int, n: int):
        self.private_key = (d, n)

    def encrypt_block(self, m: int, e: int, n: int) -> int:
        """Шифрование одного блока: c = m^e mod n."""
        return ModularArithmetic.pow_mod(m, e, n)

    def decrypt_block(self, c: int, d: int, n: int) -> int:
        """Расшифрование одного блока: m = c^d mod n."""
        return ModularArithmetic.pow_mod(c, d, n)

    def encrypt(self, text: str, key=None) -> tuple:
        """
        Шифрование текста.

        Возвращает: (encrypted_blocks, block_bits, original_bit_length)
        """
        if key is None:
            key = self.public_key
        if key is None:
            raise ValueError("Открытый ключ не задан")

        start = time.time()
        e, n = key
        blocks, block_bits, original_bit_length = MessageConverter.text_to_blocks(text, n)
        encrypted = [self.encrypt_block(m, e, n) for m in blocks]
        self.encrypt_time = time.time() - start
        return encrypted, block_bits, original_bit_length

    def decrypt(self, encrypted_blocks: list, block_bits: int, original_bit_length: int, key=None) -> str:
        """
        Расшифрование текста.

        Важно: original_bit_length используется для удаления паддинга!
        """
        if key is None:
            key = self.private_key
        if key is None:
            raise ValueError("Закрытый ключ не задан")

        start = time.time()
        d, n = key
        decrypted = [self.decrypt_block(c, d, n) for c in encrypted_blocks]
        text = MessageConverter.blocks_to_text(decrypted, block_bits, original_bit_length)
        self.decrypt_time = time.time() - start
        return text


# ============================================================
# 6. КРИПТОАНАЛИЗ (АТАКИ)
# ============================================================
class Attack:
    """
    Реализация криптоаналитических атак на RSA.

    В соответствии с заданием: реализовать атаку для случая,
    когда параметры не являются большими числами.
    """

    @staticmethod
    def factorize_bruteforce(n: int):
        """
        Атака 1: Факторизация перебором.

        Алгоритм:
        - Перебираем p от 3 до √n
        - Если n % p == 0, то q = n / p
        - Возвращаем (p, q)

        Сложность: O(√n) — работает только для маленьких n (< 50 бит).
        """
        if n.bit_length() > 50:
            return None, None
        limit = ModularArithmetic.isqrt(n)
        for p in range(3, limit + 1, 2):
            if n % p == 0:
                q = n // p
                return p, q
        return None, None

    @staticmethod
    def factorize_fermat(n: int):
        """
        Атака 2: Метод факторизации Ферма.

        Математическая основа: n = a² - b² = (a-b)(a+b)

        Алгоритм:
        1. a = ⌈√n⌉
        2. Цикл:
           b² = a² - n
           если b² — полный квадрат:
               b = √b²
               вернуть (a-b, a+b)
           a = a + 1
        """
        a = ModularArithmetic.isqrt(n) + 1
        max_iterations = 10000

        for _ in range(max_iterations):
            b2 = a * a - n
            if b2 < 0:
                a += 1
                continue
            b = ModularArithmetic.isqrt(b2)
            if b * b == b2:
                p = a - b
                q = a + b
                if p * q == n:
                    return p, q
            a += 1
        return None, None  # Не удалось факторизовать за max_iterations

    @staticmethod
    def wiener_attack(e: int, n: int):
        """
        Атака 3: Атака Винера (для маленького d).

        Условие: d < n^(1/4)
        Метод: разложение e/n в цепную дробь.
        """
        # Упрощённая версия для демонстрации
        # Полная реализация требует цепных дробей
        return None, None

    @staticmethod
    def hastad_attack(c: int, e: int = 3) -> int:
        """
        Атака 4: Атака Хастада (для e=3).

        Если m^3 < n, то c = m^3.
        Тогда m = ∛c (целочисленный кубический корень).
        """
        if e != 3:
            return None

        def integer_cuberoot(n):
            lo, hi = 0, n
            while lo <= hi:
                mid = (lo + hi) // 2
                mid3 = mid * mid * mid
                if mid3 == n:
                    return mid
                elif mid3 < n:
                    lo = mid + 1
                else:
                    hi = mid - 1
            return None

        return integer_cuberoot(c)

    @staticmethod
    def break_rsa(e: int, n: int):
        """Комбинированная атака: подбирает лучший метод."""
        # Попробуем перебор
        p, q = Attack.factorize_bruteforce(n)
        if p:
            phi = (p - 1) * (q - 1)
            d = ModularArithmetic.mod_inverse(e, phi)
            return d, p, q

        # Попробуем метод Ферма
        p, q = Attack.factorize_fermat(n)
        if p and q and p * q == n:
            phi = (p - 1) * (q - 1)
            d = ModularArithmetic.mod_inverse(e, phi)
            return d, p, q

        return None, None, None


# ============================================================
# 7. ФАЙЛОВЫЙ МЕНЕДЖЕР
# ============================================================
class FileManager:
    """Работа с файлами (сохранение/загрузка)."""

    @staticmethod
    def save_encrypted_to_file(encrypted_blocks: list, block_bits: int, original_bit_length: int, filename: str):
        """Сохраняет шифротекст в файл (с сохранением оригинальной длины!)."""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"{block_bits}\n")
            f.write(f"{original_bit_length}\n")  # <--- КЛЮЧЕВОЙ МОМЕНТ!
            f.write(','.join(str(x) for x in encrypted_blocks))
        print(f"[+] Шифротекст сохранён в {filename}")

    @staticmethod
    def load_encrypted_from_file(filename: str):
        """Загружает шифротекст из файла."""
        with open(filename, 'r', encoding='utf-8') as f:
            block_bits = int(f.readline().strip())
            original_bit_length = int(f.readline().strip())
            encrypted = [int(x) for x in f.readline().strip().split(',')]
        return encrypted, block_bits, original_bit_length

    @staticmethod
    def save_text_to_file(text: str, filename: str):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"[+] Текст сохранён в {filename}")

    @staticmethod
    def load_text_from_file(filename: str) -> str:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()



# ============================================================
# 9. АВТОМАТИЧЕСКИЕ ТЕСТЫ (TEST_MAGMA_MODES.PY)
# ============================================================
class TestRSA:
    """
    Автоматическое тестирование RSA.

    Проверяет:
    1. Шифрование и расшифрование с правильным ключом
    2. Корректность преобразования текст ↔ числа
    3. Обработку разных типов текста (русский, английский, специальные символы)
    4. Атаку на маленьком ключе
    """

    @staticmethod
    def test_encrypt_decrypt():
        """Тест: шифрование → расшифрование должно вернуть исходный текст."""
        print("\n🧪 ТЕСТ 1: Шифрование и расшифрование")
        print("-" * 50)

        # Генерируем маленький ключ для быстрого теста
        gen = RSAKeyGenerator(bits=128)
        public, private = gen.generate()

        rsa = RSA()
        rsa.set_public_key(*public)
        rsa.set_private_key(*private)

        test_messages = [
            "Hello, RSA!",
            "Привет, RSA!",
            "CRYPTOFATCAT",  # >10 символов, как требуется в задании
            "!@#$%^&*()_+",
            "1234567890"
        ]

        all_passed = True
        for msg in test_messages:
            encrypted, block_bits, orig_len = rsa.encrypt(msg)
            decrypted = rsa.decrypt(encrypted, block_bits, orig_len)
            if msg == decrypted:
                print(f"   ✅ '{msg[:20]}...' → КОРРЕКТНО")
            else:
                print(f"   ❌ '{msg}' → ОШИБКА (получено '{decrypted}')")
                all_passed = False

        return all_passed

    @staticmethod
    def test_manual_example():
        """
        Ручной пример (как в лекции на стр. 19-20).

        Используем ключи: p=61, q=53, e=17, d=2753, n=3233.
        Сообщение: "CRYPTOFATCAT" (10+ символов).
        """
        print("\n🧪 ТЕСТ 2: Ручной пример из лекции")
        print("-" * 50)

        # Используем маленькие числа для ручного расчёта
        n = 3233
        e = 17
        d = 2753

        rsa = RSA()
        rsa.set_public_key(e, n)
        rsa.set_private_key(d, n)

        message = "CRYPTOFATCAT"
        print(f"   Исходное сообщение: {message}")
        print(f"   Длина сообщения: {len(message)} символов")

        encrypted, block_bits, orig_len = rsa.encrypt(message)
        print(f"   Зашифрованные блоки: {encrypted}")
        print(f"   Размер блока: {block_bits} бит")
        print(f"   Битовая длина исходного сообщения: {orig_len}")

        decrypted = rsa.decrypt(encrypted, block_bits, orig_len)
        print(f"   Расшифрованное сообщение: {decrypted}")

        if message == decrypted:
            print("   ✅ РУЧНОЙ ПРИМЕР КОРРЕКТЕН!")
            return True
        else:
            print("   ❌ РУЧНОЙ ПРИМЕР НЕ ПРОШЁЛ!")
            return False

    @staticmethod
    def test_attack():
        """Тест атаки на маленьком ключе (как в разделе 5 отчёта)."""
        print("\n🧪 ТЕСТ 3: Демонстрация атаки")
        print("-" * 50)

        # Генерируем маленький ключ
        gen = RSAKeyGenerator(bits=16)
        public, private = gen.generate()
        e, n = public

        print(f"   Открытый ключ: e={e}, n={n}")

        p, q = Attack.factorize_bruteforce(n)

        if p and q:
            phi = (p - 1) * (q - 1)
            d = ModularArithmetic.mod_inverse(e, phi)

            print(f"   Найденные p={p}, q={q}")
            print(f"   Восстановленный d={d}")
            print(f"   Реальный d={private[0]}")

            if d == private[0]:
                print("   ✅ АТАКА УСПЕШНА!")
                return True

        print("   ❌ АТАКА НЕ УДАЛАСЬ")
        return False

    @staticmethod
    def run_all():
        """Запуск всех тестов."""
        print("\n" + "=" * 70)
        print("🧪 ЗАПУСК АВТОМАТИЧЕСКОГО ТЕСТИРОВАНИЯ RSA")
        print("=" * 70)

        results = []

        results.append(TestRSA.test_encrypt_decrypt())
        results.append(TestRSA.test_manual_example())
        results.append(TestRSA.test_attack())

        print("\n" + "=" * 70)
        print("📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
        print("=" * 70)

        passed = sum(results)
        total = len(results)
        print(f"   Успешно: {passed}/{total}")

        if passed == total:
            print("\n✅✅✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ! ✅✅✅")
        else:
            print("\n⚠️ НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОШЛИ")

        return passed == total

