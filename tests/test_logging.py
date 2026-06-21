"""Tests for the rotating error-log file handler set up in src/cli.py."""

import logging
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.cli import _setup_logging


class TestErrorLogFile(unittest.TestCase):
    """_setup_logging() should write WARNING+/ERROR+ records to a file without
    duplicating INFO/DEBUG noise, while leaving console logging untouched."""

    def setUp(self):
        self.log_path = os.path.join(tempfile.gettempdir(), "test_assetmonitor_errors.log")
        if os.path.exists(self.log_path):
            os.remove(self.log_path)
        # Reset root logger handlers between tests so repeated _setup_logging()
        # calls in the same test process don't stack file handlers.
        root = logging.getLogger()
        for h in list(root.handlers):
            root.removeHandler(h)
            h.close()

    def tearDown(self):
        root = logging.getLogger()
        for h in list(root.handlers):
            root.removeHandler(h)
            h.close()
        if os.path.exists(self.log_path):
            os.remove(self.log_path)

    def test_warning_and_error_written_info_excluded(self):
        _setup_logging("INFO", error_log_path=self.log_path, error_log_level="WARNING")
        log = logging.getLogger("test.logging.module")
        log.info("informational, should not appear in the file")
        log.warning("a warning occurred")
        log.error("an error occurred: %s", "details here")

        with open(self.log_path, encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("informational, should not appear", content)
        self.assertIn("a warning occurred", content)
        self.assertIn("an error occurred: details here", content)

    def test_error_only_level_excludes_warning(self):
        _setup_logging("INFO", error_log_path=self.log_path, error_log_level="ERROR")
        log = logging.getLogger("test.logging.module2")
        log.warning("should be excluded at ERROR level")
        log.error("should be included")

        with open(self.log_path, encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("should be excluded", content)
        self.assertIn("should be included", content)

    def test_disabled_when_path_is_none(self):
        _setup_logging("INFO", error_log_path=None)
        root = logging.getLogger()
        from logging.handlers import RotatingFileHandler
        self.assertFalse(any(isinstance(h, RotatingFileHandler) for h in root.handlers))

    def test_creates_parent_directory(self):
        nested_path = os.path.join(tempfile.gettempdir(), "am_test_log_dir", "errors.log")
        nested_dir = os.path.dirname(nested_path)
        try:
            _setup_logging("INFO", error_log_path=nested_path)
            self.assertTrue(os.path.isdir(nested_dir))
        finally:
            if os.path.exists(nested_path):
                root = logging.getLogger()
                for h in list(root.handlers):
                    root.removeHandler(h)
                    h.close()
                os.remove(nested_path)
            if os.path.isdir(nested_dir):
                os.rmdir(nested_dir)


if __name__ == '__main__':
    unittest.main(verbosity=2)
