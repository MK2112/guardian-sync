import os
import time
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, callback):
        """Initialize file change handler with callback function."""
        self.callback = callback
        self.last_modified = {}

    def _handle_event(self, event):
        """Handle file events with debouncing to filter duplicates."""
        if event.is_directory:
            return None

        path = Path(event.src_path).resolve()
        current_time = time.time()

        if path in self.last_modified:
            if current_time - self.last_modified[path] < 1:
                return None

        self.last_modified[path] = current_time
        return path

    def on_modified(self, event):
        """Handle file modification events."""
        path = self._handle_event(event)
        if path is not None:
            self.callback(path)

    def on_created(self, event):
        """Handle file creation events."""
        path = self._handle_event(event)
        if path is not None:
            self.callback(path)

    def on_deleted(self, event):
        """Handle file deletion events."""
        if event.is_directory:
            return
        path = Path(event.src_path).resolve()
        self.callback(path)


class FileMonitor:
    def __init__(self, directory, callback):
        """
        Initialize file monitor for a directory.

        Args:
            directory: Directory to monitor
            callback: Function to call when a file changes
        """
        self.directory = Path(os.path.expanduser(directory)).resolve()
        self.callback = callback
        self.observer = None

        # Create directory if it doesn't exist
        os.makedirs(self.directory, exist_ok=True)

    def start(self):
        """Start monitoring the directory."""
        event_handler = FileChangeHandler(self.callback)
        self.observer = Observer()
        self.observer.schedule(event_handler, str(self.directory), recursive=True)
        self.observer.start()
        logging.info(f"Started monitoring {self.directory}")

    def stop(self):
        """Stop monitoring the directory."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logging.info(f"Stopped monitoring {self.directory}")
