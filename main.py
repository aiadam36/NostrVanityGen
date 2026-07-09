import time
import datetime
import multiprocessing as mp
from nostr.key import PrivateKey

TARGET = "null"
NUM_WORKERS = 4

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


def _worker(target: str, target_bytes: bytes, mask_bytes: bytes,
            counter: mp.Value, done: mp.Event):
    mask_len = len(mask_bytes)
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
            with counter.get_lock():
                counter.value += batch
                total = counter.value
            print(
                f"\nFound after {total:,} attempts!\n"
                f"  npub : {pk.public_key.bech32()}\n"
                f"  nsec : {pk.bech32()}\n",
                flush=True,
            )
            done.set()
            return

        if batch % BATCH_SIZE == 0:
            with counter.get_lock():
                counter.value += BATCH_SIZE
                total = counter.value
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
    print(f"Workers   : {NUM_WORKERS}\n")

    counter = mp.Value("q", 0)
    done = mp.Event()
    start = time.time()

    workers = [
        mp.Process(
            target=_worker,
            args=(target, target_bytes, mask_bytes, counter, done),
            daemon=True,
        )
        for _ in range(NUM_WORKERS)
    ]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    print(f"Done in {time.time() - start:.1f}s")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
