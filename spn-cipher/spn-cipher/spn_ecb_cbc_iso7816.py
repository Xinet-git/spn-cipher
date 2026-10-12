"""Учебный SPN с режимами ECB и CBC. Только стандартная библиотека Python.

AES S-box: FIPS 197. Режимы ECB/CBC: NIST SP 800-38A.
Дополнение: 80 00...00 (байтовый вариант ISO/IEC 9797-1, метод 2).
HMAC-SHA256 используется для получения раундовых ключей.

Сам блочный шифр учебный: это НЕ AES. Код не предназначен для защиты
настоящих секретов и не проверяет подлинность зашифрованных данных.
"""

import hashlib
import hmac
import secrets
from pathlib import Path


BLOCK_SIZE = 16  # 16 байт = 128 бит
ROUNDS = 8

# Таблица AES S-box из FIPS 197. Индекс — входной байт, значение — выходной.
SBOX = bytes.fromhex("""
63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
""")

# Для каждой замены SBOX[x] = y записываем обратную замену INV_SBOX[y] = x.
_inverse = bytearray(256)
for _input_byte, _output_byte in enumerate(SBOX):
    _inverse[_output_byte] = _input_byte
INV_SBOX = bytes(_inverse)


def _make_pbox_table(inverse: bool) -> tuple[tuple[int, ...], ...]:
    """Готовим перестановку для каждого значения каждого входного байта.

Таблица строится один раз: при обработке блока остаётся объединить
16 заранее вычисленных частей вместо 128 операций над битами-строками.
"""
    # Нумеруем биты слева направо, от 0 до 127.
    if inverse:
        destinations = [(bit % 16) * 8 + bit // 16 for bit in range(128)]
    else:
        destinations = [(bit % 8) * 16 + bit // 8 for bit in range(128)]

    return tuple(
        tuple(
            sum(
                1 << (127 - destinations[byte_index * 8 + bit])
                for bit in range(8)
                if value & (0x80 >> bit)
            )
            for value in range(256)
        )
        for byte_index in range(BLOCK_SIZE)
    )


_PBOX_FORWARD = _make_pbox_table(inverse=False)
_PBOX_INVERSE = _make_pbox_table(inverse=True)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """Побитовый XOR двух последовательностей строго одинаковой длины."""
    if len(left) != len(right):
        raise ValueError("Для XOR нужны последовательности одинаковой длины")
    return bytes(a ^ b for a, b in zip(left, right))


def round_keys(key: bytes) -> list[bytes]:
    """Получаем из 16-байтового ключа по одному ключу на раунд и финальный XOR."""
    if len(key) != BLOCK_SIZE:
        raise ValueError("Ключ должен содержать ровно 16 байт (32 hex-символа)")
    return [
        hmac.new(key, b"SPN-demo-round-" + bytes([r]), hashlib.sha256).digest()[:16]
        for r in range(ROUNDS + 1)
    ]


def substitute(block: bytes, table: bytes) -> bytes:
    """Заменяем каждый байт согласно S-box либо обратной S-box."""
    return block.translate(table)


def p_box(block: bytes, inverse: bool = False) -> bytes:
    """Переставляем 128 бит блока; inverse=True выполняет обратный проход.

Прямой проход: 16 строк по 8 бит читаются по столбцам. Таблицы лишь
ускоряют ту же перестановку, не меняя её математического результата.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("P-box принимает ровно 16 байт")
    lookup = _PBOX_INVERSE if inverse else _PBOX_FORWARD
    result = 0
    for position, value in enumerate(block):
        result |= lookup[position][value]
    return result.to_bytes(BLOCK_SIZE, "big")


def encrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    """8 раундов: XOR, S-box и P-box (кроме последнего раунда)."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Шифруемый блок должен содержать ровно 16 байт")

    state = block
    for r in range(ROUNDS):
        state = xor_bytes(state, keys[r])
        state = substitute(state, SBOX)
        if r != ROUNDS - 1:
            state = p_box(state)
    return xor_bytes(state, keys[ROUNDS])


def decrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    """Отменяем операции шифрования блока в обратном порядке."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Шифрованный блок должен содержать ровно 16 байт")

    state = xor_bytes(block, keys[ROUNDS])
    for r in range(ROUNDS - 1, -1, -1):
        if r != ROUNDS - 1:
            state = p_box(state, inverse=True)
        state = substitute(state, INV_SBOX)
        state = xor_bytes(state, keys[r])
    return state


def pad(data: bytes) -> bytes:
    """Добавляем 80, затем нули до границы 16 байт, включая полный блок."""
    count = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + b"\x80" + b"\x00" * (count - 1)


def unpad(data: bytes) -> bytes:
    """Проверяем и удаляем завершающую последовательность 80 00...00."""
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Неверная длина дополненных данных")

    last_block = data[-BLOCK_SIZE:]
    marker = last_block.rfind(b"\x80")
    if marker == -1 or any(last_block[marker + 1:]):
        raise ValueError("Неверный ключ либо повреждены зашифрованные данные")
    return data[:len(data) - BLOCK_SIZE + marker]


def encrypt(data: bytes, key: bytes, mode: str = "CBC") -> bytes:
    """Шифруем байты; результат CBC имеет вид IV (16 байт) + шифртекст."""
    if mode not in ("ECB", "CBC"):
        raise ValueError("Режим должен быть ECB или CBC")
    keys = round_keys(key)
    iv = secrets.token_bytes(BLOCK_SIZE) if mode == "CBC" else b""
    previous = iv
    output = bytearray(iv)
    padded = pad(data)

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        if mode == "CBC":
            block = xor_bytes(block, previous)  # P_i XOR IV или P_i XOR C_(i-1)
        cipher_block = encrypt_block(block, keys)
        output.extend(cipher_block)
        previous = cipher_block
    return bytes(output)


def decrypt(data: bytes, key: bytes, mode: str = "CBC") -> bytes:
    """В CBC извлекаем IV, отменяем сцепление блоков и снимаем дополнение."""
    if mode not in ("ECB", "CBC"):
        raise ValueError("Режим должен быть ECB или CBC")
    keys = round_keys(key)
    start = BLOCK_SIZE if mode == "CBC" else 0
    if len(data) < start + BLOCK_SIZE or (len(data) - start) % BLOCK_SIZE:
        raise ValueError("Неверная длина шифртекста")

    previous = data[:BLOCK_SIZE] if mode == "CBC" else b""
    output = bytearray()
    for offset in range(start, len(data), BLOCK_SIZE):
        cipher_block = data[offset:offset + BLOCK_SIZE]
        block = decrypt_block(cipher_block, keys)
        if mode == "CBC":
            block = xor_bytes(block, previous)  # D(C_i) XOR IV или C_(i-1)
            previous = cipher_block
        output.extend(block)
    return unpad(bytes(output))


def main() -> None:
    print("SPN: 1. шифровать текст, 2. расшифровать текст")
    print("     3. шифровать файл,  4. расшифровать файл")
    action = input("Выберите действие (1–4): ").strip()
    if action not in ("1", "2", "3", "4"):
        print("Неизвестное действие")
        return

    mode = input("Режим ECB или CBC (при расшифровании тот же): ").strip().upper()
    key = bytes.fromhex(input("Ключ, ровно 32 hex-символа: ").strip())

    if action in ("1", "2"):
        if action == "1":
            plain = input("Исходный текст: ").encode("utf-8")
            print("Шифртекст в hex:", encrypt(plain, key, mode).hex())
        else:
            cipher = bytes.fromhex(input("Шифртекст в hex: ").strip())
            print("Исходный текст:", decrypt(cipher, key, mode).decode("utf-8"))
        return

    source = Path(input("Путь к исходному файлу: ").strip())
    destination = Path(input("Путь для результата: ").strip())
    if source.resolve() == destination.resolve():
        raise ValueError("Пути исходного и выходного файла должны различаться")

    raw = source.read_bytes()
    result = encrypt(raw, key, mode) if action == "3" else decrypt(raw, key, mode)
    destination.write_bytes(result)
    print("Готово. Записано байт:", len(result))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, UnicodeError, OSError) as error:
        print("Ошибка:", error)
