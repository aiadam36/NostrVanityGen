import os
import time
import datetime
import argparse
import multiprocessing as mp
from nostr.key import PrivateKey

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


def _worker(worker_id: int, target: str, target_bytes: bytes, mask_bytes: bytes,
            counters: mp.Array, done: mp.Event, result_queue: mp.Queue):
    mask_len = len(mask_bytes)
    local_count = 0
    SYNC_EVERY = 1_000

    while not done.is_set():
        pk = PrivateKey()

        raw_x = pk.public_key.raw_bytes
        match = True
        for i in range(mask_len):
            if (raw_x[i] & mask_bytes[i]) != target_bytes[i]:
                match = False
                break

        local_count += 1

        if local_count % SYNC_EVERY == 0:
            counters[worker_id] = local_count

        if match:
            counters[worker_id] = local_count
            done.set()
            result_queue.put((pk.public_key.bech32(), pk.bech32()))
            return

    counters[worker_id] = local_count


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="PREFIX",
        help="desired npub prefix to search for",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=os.cpu_count() or 4,
        metavar="N",
        help="number of parallel worker processes",
    )
    args = parser.parse_args()

    target = args.target.lower()
    num_workers = args.workers

    invalid = set(target) - BECH32_SET
    if invalid:
        bad = "', '".join(sorted(invalid))
        parser.error(
            f"target contains character(s) not in the bech32 alphabet: '{bad}'\n"
            f"\nbech32 uses only: {' '.join(sorted(BECH32_SET))}\n"
            f"Excluded characters: b i o 1"
        )

    if num_workers < 1:
        parser.error("workers must be at least 1")

    target_bytes, mask_bytes = _prefix_to_bitmask(target)

    print(f"Searching : npub1{target}...")
    print(f"Workers   : {num_workers}\n")

    counters = mp.Array("q", num_workers)
    done = mp.Event()
    result_queue = mp.Queue()
    start = time.time()

    workers = [
        mp.Process(
            target=_worker,
            args=(i, target, target_bytes, mask_bytes, counters, done, result_queue),
            daemon=True,
        )
        for i in range(num_workers)
    ]
    for w in workers:
        w.start()

    REPORT_EVERY = 1_000_000
    last_reported = 0
    while not done.is_set():
        time.sleep(0.5)
        total = sum(counters)
        if total - last_reported >= REPORT_EVERY:
            print(
                f"{datetime.datetime.now():%H:%M:%S} — "
                f"tried {total:,} keys so far",
                flush=True,
            )
            last_reported = total

    for w in workers:
        w.join()

    total = sum(counters)
    npub, nsec = result_queue.get()

    per_worker = "  |  ".join(
        f"w{i+1}: {counters[i]:,}" for i in range(num_workers)
    )
    print(
        f"\nFound after {total:,} total attempts!\n"
        f"  {per_worker}\n"
        f"\n  npub : {npub}\n"
        f"  nsec : {nsec}\n",
        flush=True,
    )
    print(f"Done in {time.time() - start:.1f}s")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
