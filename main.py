import time
import datetime
from threading import Event, Lock, Thread
from nostr.key import PrivateKey

TARGET = "null"
NUM_THREADS = 4

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_VALUES = {c: i for i, c in enumerate(BECH32_CHARSET)}
BECH32_SET = frozenset(BECH32_CHARSET)


def _prefix_to_bitmask(prefix: str):
    bits5 = [BECH32_VALUES[c] for c in prefix]
    total_bits = len(prefix) * 5
    full_bytes = total_bits // 8
    remainder = total_bits % 8

    val = 0
    for b in bits5:
        val = (val << 5) | b

    if remainder == 0:
        target_bytes = val.to_bytes(full_bytes, "big")
        mask_bytes = bytes([0xFF] * full_bytes)
    else:
        shift = 8 - remainder
        target_bytes = (val << shift).to_bytes(full_bytes + 1, "big")
        mask_bytes = bytes([0xFF] * full_bytes + [(0xFF << shift) & 0xFF])

    return target_bytes, mask_bytes


class _Counter:
    def __init__(self):
        self.n = 0
        self._lock = Lock()

    def increment(self, step=1):
        with self._lock:
            self.n += step
            return self.n


class _Worker(Thread):
    def __init__(self, target: str, target_bytes: bytes, mask_bytes: bytes,
                 counter: _Counter, done: Event):
        super().__init__(daemon=True)
        self.target = target
        self.target_bytes = target_bytes
        self.mask_bytes = mask_bytes
        self.counter = counter
        self.done = done

    def run(self):
        target_bytes = self.target_bytes
        mask_bytes = self.mask_bytes
        mask_len = len(mask_bytes)
        done = self.done
        counter = self.counter

        batch = 0
        BATCH_SIZE = 10_000

        while not done.is_set():
            pk = PrivateKey()

            raw_x = pk.public_key.raw_bytes
            match = True
            for i in range(mask_len):
                if (raw_x[i] & mask_bytes[i]) != target_bytes[i]:
                    match = False
                    break

            batch += 1

            if match:
                total = counter.increment(batch)
                print(
                    f"\nFound after {total:,} attempts!\n"
                    f"  npub : {pk.public_key.bech32()}\n"
                    f"  nsec : {pk.bech32()}\n",
                    flush=True,
                )
                done.set()
                return

            if batch % BATCH_SIZE == 0:
                total = counter.increment(BATCH_SIZE)
                if total % 1_000_000 < BATCH_SIZE:
                    print(
                        f"{datetime.datetime.now():%H:%M:%S} — "
                        f"tried {total:,} keys so far",
                        flush=True,
                    )
                batch = 0


def main():
    target = TARGET.lower()

    invalid = set(target) - BECH32_SET
    if invalid:
        bad = "', '".join(sorted(invalid))
        print(
            f"Error: target contains character(s) not in the bech32 alphabet: '{bad}'\n"
            f"\nbech32 uses only: {' '.join(sorted(BECH32_SET))}\n"
            f"Excluded characters: b i o 1"
        )
        return

    target_bytes, mask_bytes = _prefix_to_bitmask(target)

    print(f"Searching : npub1{target}...")
    print(f"Threads   : {NUM_THREADS}\n")

    counter = _Counter()
    done = Event()
    start = time.time()

    threads = [
        _Worker(target, target_bytes, mask_bytes, counter, done)
        for _ in range(NUM_THREADS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"Done in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()
