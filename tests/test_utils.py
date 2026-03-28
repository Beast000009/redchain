"""Tests for redchain/utils.py — platform detection and tool helpers."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import (
    PLATFORM, IS_MAC, IS_LINUX, IS_WINDOWS, IS_WSL,
    find_tool, require_sudo, setup_platform_env, get_platform_temp_dir
)


class TestPlatformDetection(unittest.TestCase):
    """Test platform detection constants."""
    
    def test_platform_is_string(self):
        self.assertIsInstance(PLATFORM, str)
        self.assertIn(PLATFORM, ["Darwin", "Linux", "Windows"])
    
    def test_exactly_one_platform_true(self):
        """Only one of IS_MAC, IS_LINUX, IS_WINDOWS should be True."""
        platforms = [IS_MAC, IS_LINUX, IS_WINDOWS]
        self.assertEqual(sum(platforms), 1, 
                        f"Expected exactly one True, got: MAC={IS_MAC}, LINUX={IS_LINUX}, WIN={IS_WINDOWS}")
    
    def test_wsl_only_on_linux(self):
        """WSL detection should only be True on Linux."""
        if IS_WSL:
            self.assertTrue(IS_LINUX, "IS_WSL is True but IS_LINUX is False")
        if not IS_LINUX:
            self.assertFalse(IS_WSL, "IS_WSL should be False on non-Linux")


class TestFindTool(unittest.TestCase):
    """Test the find_tool utility."""
    
    def test_find_python(self):
        """Python should always be findable."""
        result = find_tool("python3") or find_tool("python")
        self.assertIsNotNone(result)
    
    def test_find_nonexistent_tool(self):
        """A made-up tool should return None."""
        result = find_tool("redchain_nonexistent_tool_xyz_42")
        self.assertIsNone(result)
    
    def test_returns_string_or_none(self):
        result = find_tool("nmap")
        self.assertTrue(result is None or isinstance(result, str))


class TestRequireSudo(unittest.TestCase):
    """Test root detection."""
    
    def test_returns_bool(self):
        result = require_sudo()
        self.assertIsInstance(result, bool)
    
    def test_non_root_returns_false(self):
        """In CI/dev, we're typically not root."""
        if not IS_WINDOWS and os.getuid() != 0:
            self.assertFalse(require_sudo())


class TestSetupPlatformEnv(unittest.TestCase):
    """Test platform-specific environment setup."""
    
    def test_does_not_crash(self):
        """setup_platform_env should not raise on any platform."""
        setup_platform_env()  # Should not raise
    
    def test_dyld_only_on_mac(self):
        """DYLD_FALLBACK_LIBRARY_PATH should only be set on macOS."""
        if IS_MAC:
            setup_platform_env()
            self.assertIn("/opt/homebrew/lib", 
                         os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", ""))


class TestGetPlatformTempDir(unittest.TestCase):
    """Test temp directory helper."""
    
    def test_returns_existing_dir(self):
        tmpdir = get_platform_temp_dir()
        self.assertTrue(os.path.isdir(tmpdir))


if __name__ == "__main__":
    unittest.main()
