"""
Модульное тестирование классов RSA.

Тестирует каждый класс отдельно:
1. ModularArithmetic - модульная арифметика
2. PrimeGenerator - генерация простых чисел
3. MessageConverter - преобразование текст ↔ числа
4. RSAKeyGenerator - генерация ключей
5. RSA - шифрование/расшифрование
6. Attack - криптоаналитические атаки
7. FileManager - работа с файлами
"""

import unittest
import tempfile
import os
import random
from rsa_code import (
    ModularArithmetic, PrimeGenerator, MessageConverter,
    RSAKeyGenerator, RSA, Attack, FileManager
)


class TestModularArithmetic(unittest.TestCase):
    """Тесты для класса ModularArithmetic."""

    def test_gcd(self):
        """Тест алгоритма Евклида."""
        self.assertEqual(ModularArithmetic.gcd(48, 18), 6)
        self.assertEqual(ModularArithmetic.gcd(17, 3120), 1)
        self.assertEqual(ModularArithmetic.gcd(100, 25), 25)
        self.assertEqual(ModularArithmetic.gcd(0, 5), 5)

    def test_extended_gcd(self):
        """Тест расширенного алгоритма Евклида."""
        d, x, y = ModularArithmetic.extended_gcd(17, 3120)
        self.assertEqual(d, 1)
        self.assertEqual(17 * x + 3120 * y, 1)

        d, x, y = ModularArithmetic.extended_gcd(48, 18)
        self.assertEqual(d, 6)
        self.assertEqual(48 * x + 18 * y, 6)

    def test_mod_inverse(self):
        """Тест нахождения обратного элемента."""
        # 17 * 2753 ≡ 1 mod 3120
        self.assertEqual(ModularArithmetic.mod_inverse(17, 3120), 2753)
        # 13 * 1637 ≡ 1 mod 21280
        self.assertEqual(ModularArithmetic.mod_inverse(13, 21280), 1637)

        with self.assertRaises(ValueError):
            ModularArithmetic.mod_inverse(2, 4)  # НОД(2,4)=2

    def test_pow_mod(self):
        """Тест быстрого возведения в степень по модулю."""
        # 5^13 mod 23 = 21
        self.assertEqual(ModularArithmetic.pow_mod(5, 13, 23), 21)
        # 2^10 mod 1024 = 0? 2^10=1024, 1024 mod 1024 = 0
        self.assertEqual(ModularArithmetic.pow_mod(2, 10, 1024), 0)
        # a^1 mod m = a mod m
        self.assertEqual(ModularArithmetic.pow_mod(123, 1, 1000), 123)

    def test_isqrt(self):
        """Тест целочисленного квадратного корня."""
        self.assertEqual(ModularArithmetic.isqrt(16), 4)
        self.assertEqual(ModularArithmetic.isqrt(17), 4)
        self.assertEqual(ModularArithmetic.isqrt(3233), 56)
        self.assertEqual(ModularArithmetic.isqrt(0), 0)


class TestPrimeGenerator(unittest.TestCase):
    """Тесты для класса PrimeGenerator."""

    def test_miller_rabin_small_primes(self):
        """Тест Миллера-Рабина на малых простых числах."""
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        for p in primes:
            self.assertTrue(PrimeGenerator.miller_rabin(p, k=5))

    def test_miller_rabin_composite(self):
        """Тест Миллера-Рабина на составных числах."""
        composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 22, 24, 25]
        for c in composites:
            self.assertFalse(PrimeGenerator.miller_rabin(c, k=5))

    def test_miller_rabin_carmichael(self):
        """Тест на числах Кармайкла (тест Ферма ошибается, Миллер-Рабин нет)."""
        carmichael_numbers = [561, 1105, 1729, 2465, 2821, 6601]
        for c in carmichael_numbers:
            self.assertFalse(PrimeGenerator.miller_rabin(c, k=10))

    def test_miller_rabin_61(self):
        """Ручной пример из лекции: n=61."""
        self.assertTrue(PrimeGenerator.miller_rabin(61, k=5))

    def test_generate_prime(self):
        """Тест генерации простых чисел разной длины."""
        for bits in [8, 16, 32, 64]:
            p = PrimeGenerator.generate_prime(bits)
            self.assertTrue(PrimeGenerator.miller_rabin(p))
            self.assertEqual(p.bit_length(), bits)


class TestMessageConverter(unittest.TestCase):
    """Тесты для класса MessageConverter."""

    def test_text_to_blocks_crypto(self):
        """Тест с примером CRYPTO из лекции."""
        n = 21583  # p=113, q=191
        blocks, block_bits, orig_len = MessageConverter.text_to_blocks("CRYPTO", n)

        # Размер блока: ⌊log2 21583⌋ = 14
        self.assertEqual(block_bits, 14)
        self.assertEqual(orig_len, 48)  # 6 символов * 8 бит

        # Блоки в порядке [m4, m3, m2, m1] как в лекции
        # m4=16, m3=13605, m2=9537, m1=5199
        self.assertEqual(blocks, [16, 13605, 9537, 5199])

    def test_blocks_to_text_crypto(self):
        """Тест обратного преобразования с примером CRYPTO."""
        blocks = [16, 13605, 9537, 5199]
        block_bits = 14
        orig_len = 48

        text = MessageConverter.blocks_to_text(blocks, block_bits, orig_len)
        self.assertEqual(text, "CRYPTO")

    def test_text_to_blocks_single_char(self):
        """Тест с одним символом."""
        n = 21583
        blocks, block_bits, orig_len = MessageConverter.text_to_blocks("A", n)
        # 'A' = 65 = 01000001, 8 бит
        self.assertEqual(orig_len, 8)
        self.assertEqual(blocks, [65])  # один блок

    def test_blocks_to_text_single_char(self):
        """Тест обратного преобразования с одним символом."""
        text = MessageConverter.blocks_to_text([65], 8, 8)
        self.assertEqual(text, "A")

    def test_get_block_bits(self):
        """Тест получения размера блока."""
        self.assertEqual(MessageConverter.get_block_bits(21583), 14)
        self.assertEqual(MessageConverter.get_block_bits(256), 8)
        self.assertEqual(MessageConverter.get_block_bits(255), 7)

    def test_get_display_bits(self):
        """Тест получения размера для вывода."""
        self.assertEqual(MessageConverter.get_display_bits(21583), 15)
        self.assertEqual(MessageConverter.get_display_bits(256), 9)

    def test_parse_encrypted_input(self):
        """Тест парсинга ввода шифротекста."""
        self.assertEqual(MessageConverter.parse_encrypted_input("1,2,3"), [1, 2, 3])
        self.assertEqual(MessageConverter.parse_encrypted_input("[1,2,3]"), [1, 2, 3])
        self.assertEqual(MessageConverter.parse_encrypted_input("1 2 3"), [1, 2, 3])


class TestRSAKeyGenerator(unittest.TestCase):
    """Тесты для класса RSAKeyGenerator."""

    def test_generate_small_keys(self):
        """Тест генерации ключей малого размера."""
        gen = RSAKeyGenerator(bits=16)
        public, private = gen.generate()

        e, n = public
        d, n2 = private

        self.assertEqual(n, n2)
        self.assertGreaterEqual(n.bit_length(), 16)
        self.assertEqual(ModularArithmetic.gcd(e, (gen.p - 1) * (gen.q - 1)), 1)
        # Проверка: e*d ≡ 1 mod φ(n)
        self.assertEqual(
            (e * d) % ((gen.p - 1) * (gen.q - 1)), 1
        )

    def test_rsa_example_lecture(self):
        """Тест с примером из лекции: p=113, q=191, e=13."""
        # Вручную задаём ключи
        e, n = 13, 21583
        d = 1637

        self.assertEqual(ModularArithmetic.mod_inverse(e, 21280), d)
        self.assertEqual(n, 113 * 191)


class TestRSA(unittest.TestCase):
    """Тесты для класса RSA."""

    def setUp(self):
        """Подготовка тестовых ключей."""
        # Маленькие ключи для тестов
        self.n = 21583
        self.e = 13
        self.d = 1637

        self.rsa = RSA()
        self.rsa.set_public_key(self.e, self.n)
        self.rsa.set_private_key(self.d, self.n)

    def test_encrypt_block(self):
        """Тест шифрования блока."""
        # m = 5199 → c = 5199^13 mod 21583
        c = self.rsa.encrypt_block(5199, self.e, self.n)
        self.assertEqual(c, 2148)

    def test_decrypt_block(self):
        """Тест расшифрования блока."""
        m = self.rsa.decrypt_block(2148, self.d, self.n)
        self.assertEqual(m, 5199)

    def test_encrypt_crypto(self):
        """Тест шифрования строки CRYPTO."""
        encrypted, block_bits, orig_len = self.rsa.encrypt("CRYPTO")

        # Ожидаемые значения из лекции (c4, c3, c2, c1)
        expected = [12649, 5288, 12068, 2148]
        self.assertEqual(encrypted, expected)
        self.assertEqual(block_bits, 14)
        self.assertEqual(orig_len, 48)

    def test_decrypt_crypto(self):
        """Тест расшифрования строки CRYPTO."""
        encrypted = [12649, 5288, 12068, 2148]
        decrypted = self.rsa.decrypt(encrypted, 14, 48)
        self.assertEqual(decrypted, "CRYPTO")

    def test_encrypt_decrypt_cycle(self):
        """Тест цикла: шифрование → расшифрование."""
        messages = ["Hello", "Привет", "RSA", "12345"]

        for msg in messages:
            encrypted, block_bits, orig_len = self.rsa.encrypt(msg)
            decrypted = self.rsa.decrypt(encrypted, block_bits, orig_len)
            self.assertEqual(msg, decrypted)


class TestAttack(unittest.TestCase):
    """Тесты для класса Attack."""

    def test_factorize_bruteforce(self):
        """Тест факторизации перебором."""
        n = 3233  # 53 * 61
        p, q = Attack.factorize_bruteforce(n)
        self.assertIn(p, [53, 61])
        self.assertIn(q, [53, 61])
        self.assertEqual(p * q, n)

    def test_factorize_bruteforce_large(self):
        """Тест факторизации большого числа (возвращает None)."""
        n = 21583  # 113 * 191, но > 50 бит? 21583 ~ 15 бит
        p, q = Attack.factorize_bruteforce(n)
        # Должен найти, т.к. 15 бит < 50
        self.assertIsNotNone(p)

    def test_factorize_fermat(self):
        """Тест метода Ферма."""
        n = 3233  # 53 * 61 (разница 8)
        p, q = Attack.factorize_fermat(n)
        self.assertIn(p, [53, 61])
        self.assertIn(q, [53, 61])

    def test_hastad_attack(self):
        """Тест атаки Хастада."""
        # m=42, m³=74088
        c = 74088
        m = Attack.hastad_attack(c, e=3)
        self.assertEqual(m, 42)

    def test_hastad_attack_wrong_e(self):
        """Тест атаки Хастада с e != 3."""
        m = Attack.hastad_attack(74088, e=17)
        self.assertIsNone(m)


class TestFileManager(unittest.TestCase):
    """Тесты для класса FileManager."""

    def setUp(self):
        """Создание временного файла."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "test.txt")

    def tearDown(self):
        """Удаление временного файла."""
        self.temp_dir.cleanup()

    def test_save_and_load_text(self):
        """Тест сохранения и загрузки текста."""
        original = "Hello, RSA!"
        FileManager.save_text_to_file(original, self.test_file)
        loaded = FileManager.load_text_from_file(self.test_file)
        self.assertEqual(original, loaded)

    def test_save_and_load_encrypted(self):
        """Тест сохранения и загрузки шифротекста."""
        encrypted = [2148, 12068, 5288, 12649]
        block_bits = 14
        orig_len = 48

        FileManager.save_encrypted_to_file(encrypted, block_bits, orig_len, self.test_file)
        loaded_enc, loaded_bits, loaded_len = FileManager.load_encrypted_from_file(self.test_file)

        self.assertEqual(loaded_enc, encrypted)
        self.assertEqual(loaded_bits, block_bits)
        self.assertEqual(loaded_len, orig_len)


class TestIntegration(unittest.TestCase):
    """Интеграционные тесты (взаимодействие классов)."""

    def test_full_rsa_cycle_with_generated_keys(self):
        """Полный цикл: генерация ключей → шифрование → расшифрование."""
        gen = RSAKeyGenerator(bits=32)
        public, private = gen.generate()

        rsa = RSA()
        rsa.set_public_key(*public)
        rsa.set_private_key(*private)

        message = "Test message for RSA encryption!"

        encrypted, block_bits, orig_len = rsa.encrypt(message)
        decrypted = rsa.decrypt(encrypted, block_bits, orig_len)

        self.assertEqual(message, decrypted)

    def test_manual_key_mode_simulation(self):
        """Симуляция ручного режима: p=61, q=53, e=17."""
        p, q = 61, 53
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 17
        d = ModularArithmetic.mod_inverse(e, phi)

        rsa = RSA()
        rsa.set_public_key(e, n)
        rsa.set_private_key(d, n)

        message = "CRYPTO"
        encrypted, block_bits, orig_len = rsa.encrypt(message)
        decrypted = rsa.decrypt(encrypted, block_bits, orig_len)

        self.assertEqual(message, decrypted)


def run_all_tests():
    """Запуск всех тестов."""
    print("\n" + "=" * 70)
    print("🧪 ЗАПУСК МОДУЛЬНЫХ ТЕСТОВ RSA")
    print("=" * 70)

    # Создаём тестовый набор
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Добавляем все тесты
    suite.addTests(loader.loadTestsFromTestCase(TestModularArithmetic))
    suite.addTests(loader.loadTestsFromTestCase(TestPrimeGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestMessageConverter))
    suite.addTests(loader.loadTestsFromTestCase(TestRSAKeyGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestRSA))
    suite.addTests(loader.loadTestsFromTestCase(TestAttack))
    suite.addTests(loader.loadTestsFromTestCase(TestFileManager))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    # Запускаем
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Вывод результата
    print("\n" + "=" * 70)
    print("📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
    print("=" * 70)
    print(f"   Успешно: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"   Всего: {result.testsRun}")
    print(f"   Ошибок: {len(result.errors)}")
    print(f"   Провалено: {len(result.failures)}")

    if result.wasSuccessful():
        print("\n✅✅✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ! ✅✅✅")
    else:
        print("\n⚠️ ЕСТЬ ОШИБКИ!")

    return result.wasSuccessful()


if __name__ == "__main__":
    run_all_tests()