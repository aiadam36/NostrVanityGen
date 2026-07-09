import time
import datetime
from threading import Event, Lock, Thread
from nostr.key import PrivateKey

TARGET = "null"
NUM_THREADS = 4

BECH32_CHARSET = frozenset("qpzry9x8gf2tvdw0s3jn54khce6mua7l")


class _Counter:
    def __init__(self):
        self.n = 0
        self._lock = Lock()

    def increment(self, step=1):
        with self._lock:
            self.n += step
            return self.n


class _Worker(Thread):
    def __init__(self, target: str, counter: _Counter, done: Event):
        super().__init__(daemon=True)
        self.target = target
        self.counter = counter
        self.done = done

    def run(self):
        length = len(self.target)
        batch = 0
        BATCH_SIZE = 10_000

        while not self.done.is_set():
            pk = PrivateKey()
            npub_body = pk.public_key.bech32()[5:]  # strip "npub1"
            batch += 1

            if npub_body[:length] == self.target:
                total = self.counter.increment(batch)
                print(
                    f"\nFound after {total:,} attempts!\n"
                    f"  npub : {pk.public_key.bech32()}\n"
                    f"  nsec : {pk.bech32()}\n",
                    flush=True,
                )
                self.done.set()
                return

            if batch % BATCH_SIZE == 0:
                total = self.counter.increment(BATCH_SIZE)
                if total % 1_000_000 < BATCH_SIZE:
                    print(
                        f"{datetime.datetime.now():%H:%M:%S} — "
                        f"tried {total:,} keys so far",
                        flush=True,
                    )
                batch = 0


def main():
    target = TARGET.lower()

    invalid = set(target) - BECH32_CHARSET
    if invalid:
        bad = "', '".join(sorted(invalid))
        print(
            f"Error: target contains character(s) not in the bech32 alphabet: '{bad}'\n"
            f"\nbech32 uses only: {' '.join(sorted(BECH32_CHARSET))}\n"
            f"Excluded characters: b i o 1"
        )
        return

    print(f"Searching : npub1{target}...")
    print(f"Threads   : {NUM_THREADS}\n")

    counter = _Counter()
    done = Event()
    start = time.time()

    threads = [_Worker(target, counter, done) for _ in range(NUM_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"Done in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()
