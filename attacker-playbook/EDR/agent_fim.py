#!/usr/bin/env python3
# Owner: Louis. Watches the Juice Shop upload folder and emits file_change
# events for the engine. Hashes on the watchdog "closed" event (Linux
# close-write), with a size-stable retry fallback for other backends.

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from edr_core import Agent, Event
import hashlib
import os
import queue
import time

# CONFIRM the real Juice Shop upload folder on the VM and set it here.
WATCH_DIR = "/home/juice/juice-shop/uploads"


def hash_file_now(path):
    h = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest(), size
    except OSError:
        return None, None


def hash_file_retry(path):
    last_size = -1
    for _ in range(10):
        try:
            current_size = os.path.getsize(path)
        except OSError:
            return None, None
        if current_size == last_size:
            break
        last_size = current_size
        time.sleep(0.2)
    return hash_file_now(path)


class FimHandler(FileSystemEventHandler):
    def __init__(self, event_queue, known_hashes):
        self.event_queue = event_queue
        self.known_hashes = known_hashes
        self.closed_supported = False

    def _emit(self, observed_at, path, change, sha256, size):
        self.event_queue.put((observed_at, path, change, sha256, size))

    def on_created(self, event):
        return  # wait for on_closed / the on_modified fallback

    def on_closed(self, event):
        if event.is_directory:
            return
        self.closed_supported = True
        observed_at = time.time()
        path = event.src_path
        sha256, size = hash_file_now(path)
        if sha256 is not None and self.known_hashes.get(path) == sha256:
            return  # the modified fallback already reported this exact file
        change = "modified" if path in self.known_hashes else "created"
        self.known_hashes[path] = sha256
        self._emit(observed_at, path, change, sha256, size)

    def on_modified(self, event):
        if event.is_directory or self.closed_supported:
            return
        observed_at = time.time()
        path = event.src_path
        sha256, size = hash_file_retry(path)
        change = "modified" if path in self.known_hashes else "created"
        self.known_hashes[path] = sha256
        self._emit(observed_at, path, change, sha256, size)

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = event.src_path
        self.known_hashes.pop(path, None)
        self._emit(time.time(), path, "deleted", None, None)

    def on_moved(self, event):
        if event.is_directory:
            return  # reported as created at the destination path
        dest = event.dest_path
        sha256, size = hash_file_retry(dest)
        self.known_hashes[dest] = sha256
        self._emit(time.time(), dest, "created", sha256, size)


class FileIntegrityAgent(Agent):
    name = "fim-agent"

    def __init__(self, interval: float = 2.0, watch_dirs=None):
        super().__init__(interval)
        self.watch_dirs = watch_dirs or [WATCH_DIR]
        self.known_hashes = {}
        self.event_queue = queue.Queue()
        self.observer = Observer()

        handler = FimHandler(self.event_queue, self.known_hashes)
        watched = 0
        for d in self.watch_dirs:
            # A missing/unwatchable folder must not crash the whole EDR.
            try:
                os.makedirs(d, exist_ok=True)
                self.observer.schedule(handler, d, recursive=True)
                watched += 1
                print(f"[fim-agent] watching {d}")
            except Exception as err:
                print(f"[fim-agent] cannot watch {d}: {err} (skipping)")
        try:
            self.observer.start()
        except Exception as err:
            print(f"[fim-agent] observer failed to start: {err}")
        if watched == 0:
            print("[fim-agent] no folders watched; file-upload detection is OFF")

    def collect(self) -> list:
        try:
            events = []
            while not self.event_queue.empty():
                observed_at, path, change, sha256, size = self.event_queue.get_nowait()
                events.append(Event(
                    agent=self.name, event_type="file_change", observed_at=observed_at,
                    data={"path": path, "change": change, "sha256": sha256, "size": size},
                ))
            return events
        except Exception as e:
            print(f"[fim-agent] collect() error: {e}")
            return []

    def stop(self):
        try:
            self.observer.stop()
            self.observer.join()
        except Exception:
            pass
