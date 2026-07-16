import hashlib
import ipaddress
import json
import math
import time
from pathlib import Path
from typing import Callable, Generator, Tuple

LOG_FILE = Path("lms-stage-access.log")


class HyperLogLog:
    def __init__(self, p: int = 14):
        if not (4 <= p <= 20):
            raise ValueError("p must be in [4, 20]")
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m

        if self.m == 16:
            self.alpha = 0.673
        elif self.m == 32:
            self.alpha = 0.697
        elif self.m == 64:
            self.alpha = 0.709
        else:
            self.alpha = 0.7213 / (1.0 + 1.079 / self.m)

    def add(self, value: str) -> None:
        x = int.from_bytes(hashlib.md5(value.encode("utf-8")).digest()[:8], "big")
        idx = x >> (64 - self.p)
        w = x & ((1 << (64 - self.p)) - 1)

        bits = 64 - self.p
        rank = bits - w.bit_length() + 1 if w else bits + 1

        if rank > self.registers[idx]:
            self.registers[idx] = rank

    def count(self) -> int:
        indicator = sum(2.0**-r for r in self.registers)
        estimate = self.alpha * self.m * self.m / indicator

        if estimate <= 2.5 * self.m:
            zeros = self.registers.count(0)
            if zeros > 0:
                estimate = self.m * math.log(self.m / zeros)

        return round(estimate)


def is_valid_ip(value: str) -> bool:
    if "." not in value and ":" not in value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def load_ip_addresses(path: Path) -> Generator[str, None, None]:
    if not path.exists():
        return

    with path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            try:
                record = json.loads(line)
                ip = record.get("remote_addr")
                if isinstance(ip, str) and is_valid_ip(ip):
                    yield ip
            except json.JSONDecodeError:
                continue


def exact_count(path: Path) -> int:
    return len(set(load_ip_addresses(path)))


def hll_count(path: Path, p: int = 14) -> int:
    hll = HyperLogLog(p=p)
    for ip in load_ip_addresses(path):
        hll.add(ip)
    return hll.count()


def timed(func: Callable, *args, **kwargs) -> Tuple[int, float]:
    start = time.perf_counter()
    result = func(*args, **kwargs)
    elapsed = time.perf_counter() - start
    return result, elapsed


def main() -> None:
    if not LOG_FILE.exists():
        print(f"Помилка: Файл '{LOG_FILE}' не знайдено.")
        return

    exact_result, exact_time = timed(exact_count, LOG_FILE)
    hll_result, hll_time = timed(hll_count, LOG_FILE)

    error = abs(hll_result - exact_result) / exact_result * 100 if exact_result else 0.0

    print("Результати порівняння:")
    print(f"{'':30} {'Точний підрахунок':>20} {'HyperLogLog':>15}")
    print(
        f"{'Унікальні елементи':30} {float(exact_result):>20.1f} {float(hll_result):>15.1f}"
    )
    print(f"{'Час виконання (сек.)':30} {exact_time:>20.2f} {hll_time:>15.2f}")
    print(f"{'Похибка (%)':30} {0.0:>20.2f} {error:>15.2f}")


if __name__ == "__main__":
    main()
