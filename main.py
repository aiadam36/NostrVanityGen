import time
import datetime
from threading import Event, Lock, Thread
from nostr.key import PrivateKey

TARGET = "null"
NUM_THREADS = 4


class _Counter:
    def __init__(self):
        self.n = 0
        self._lock = Lock()

    def increment(self, step=10_000):
        with self._lock:
            self.n += step


class _Worker(Thread):
    def __init__(self, target: str, counter: _Counter, done: Event):
        super().__init__(daemon=True)
        self.target = target
        self.counter = counter
        self.done = done

    def run(self):
        i = 0
        length = len(self.target)

        while not self.done.is_set():
            pk = PrivateKey()
            npub_body = pk.public_key.bech32()[5:]  # strip "npub1"

            if npub_body[:length] == self.target:
                print(
                    f"\nFound after {self.counter.n:,} attempts!\n"
                    f"  npub : {pk.public_key.bech32()}\n"
                    f"  nsec : {pk.bech32()}\n",
                    flush=True,
                )
                self.done.set()
                return

            i += 1
            if i % 10_000 == 0:
                self.counter.increment()
                if self.counter.n % 1_000_000 == 0:
                    print(
                        f"{datetime.datetime.now():%H:%M:%S} — "
                        f"tried {self.counter.n:,} keys so far",
                        flush=True,
                    )


def main():
    target = TARGET.lower()
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
