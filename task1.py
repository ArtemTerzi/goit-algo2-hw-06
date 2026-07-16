import hashlib
from typing import Generator, List, Dict


class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("size має бути додатним цілим числом")

        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("num_hashes має бути додатним цілим числом")

        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bytearray((size + 7) // 8)

    def _hashes(self, item: str) -> Generator[int, None, None]:
        digest = hashlib.sha256(item.encode("utf-8")).digest()

        h1 = int.from_bytes(digest[:8], byteorder="big")
        h2 = int.from_bytes(digest[8:16], byteorder="big")

        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.size

    def add(self, item: str) -> None:
        if not isinstance(item, str) or not item:
            return

        for index in self._hashes(item):
            byte_index = index // 8
            bit_index = index % 8
            self.bit_array[byte_index] |= 1 << bit_index

    def __contains__(self, item: str) -> bool:
        if not isinstance(item, str) or not item:
            return False

        for index in self._hashes(item):
            byte_index = index // 8
            bit_index = index % 8
            if not (self.bit_array[byte_index] & (1 << bit_index)):
                return False
        return True


def check_password_uniqueness(
    bloom_filter: BloomFilter, passwords: List[str]
) -> Dict[str, str]:
    if not isinstance(bloom_filter, BloomFilter):
        raise TypeError("bloom_filter має бути екземпляром BloomFilter")

    if not isinstance(passwords, list):
        raise TypeError("passwords має бути списком")

    results = {}
    for password in passwords:
        if not isinstance(password, str) or not password:
            results[str(password)] = "некоректне значення"
            continue

        if password in bloom_filter:
            results[password] = "вже використаний"
        else:
            results[password] = "унікальний"
            bloom_filter.add(password)

    return results


if __name__ == "__main__":
    bloom = BloomFilter(size=1000, num_hashes=3)

    existing_passwords = ["password123", "admin123", "qwerty123"]
    for pwd in existing_passwords:
        bloom.add(pwd)

    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest", ""]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    for pwd, status in results.items():
        print(f"Пароль '{pwd}' - {status}.")
