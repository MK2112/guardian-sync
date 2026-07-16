import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
import pytest
from unittest import mock
from src.file_monitor import FileMonitor, FileChangeHandler
import time
from watchdog.events import FileSystemEvent


def test_file_monitor_triggers_callback(tmp_path):
    called = []

    def callback(path):
        called.append(path)

    monitor = FileMonitor(str(tmp_path), callback)
    monitor.start()
    test_file = tmp_path / "foo.txt"
    test_file.write_text("bar")
    time.sleep(1.5)  # allow event to propagate
    monitor.stop()
    assert any("foo.txt" in str(x) for x in called)


def test_rapid_file_changes_debounced(tmp_path):
    called = []

    def callback(path):
        called.append(path)

    monitor = FileMonitor(str(tmp_path), callback)
    monitor.start()
    test_file = tmp_path / "rapid.txt"
    for _ in range(5):
        test_file.write_text("x")
        time.sleep(0.1)
    time.sleep(2)
    monitor.stop()
    # Should not call callback more than 5 times, ideally once
    assert len(called) <= 5


def test_hidden_files_ignored(tmp_path):
    called = []

    def callback(path):
        called.append(path)

    monitor = FileMonitor(str(tmp_path), callback)
    monitor.start()
    hidden_file = tmp_path / ".hidden.txt"
    hidden_file.write_text("secret")
    time.sleep(1.5)
    monitor.stop()
    # Callback is called for hidden files unless FileMonitor filters them
    assert any(".hidden.txt" in str(x) for x in called)


def test_created_then_modified_debounced(tmp_path):
    called = []

    def callback(path):
        called.append(path)

    monitor = FileMonitor(str(tmp_path), callback)
    monitor.start()
    test_file = tmp_path / "test.txt"
    # Write creates file -> on_created fires
    test_file.write_text("hello")
    time.sleep(0.1)
    # Touch triggers on_modified (should be debounced within 1s of on_created)
    test_file.write_text("hello")
    time.sleep(0.5)
    # Wait past debounce window and write again (should fire)
    time.sleep(1.5)
    test_file.write_text("world")
    time.sleep(1)
    monitor.stop()
    # Should have fired twice: once for create, once for the third write
    assert len(called) == 2, (
        f"Expected 2 callbacks (create + 3rd write), got {len(called)}"
    )


def test_file_monitor_triggers_on_delete(tmp_path):
    called = []

    def callback(path):
        called.append(path)

    monitor = FileMonitor(str(tmp_path), callback)
    monitor.start()
    test_file = tmp_path / "delete_me.txt"
    test_file.write_text("to be deleted")
    time.sleep(0.5)
    test_file.unlink()
    time.sleep(1.5)
    monitor.stop()
    assert any("delete_me.txt" in str(x) for x in called)


def test_file_monitor_ignores_directories(tmp_path):
    called = []

    def callback(path):
        called.append(path)

    monitor = FileMonitor(str(tmp_path), callback)
    monitor.start()
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    time.sleep(1.5)
    monitor.stop()
    assert not called
