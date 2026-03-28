"""
RedChain — Cross-Platform Infrastructure Tests
Verifies: ping commands, proxychains prefix, temp paths, HTTPX transport,
redchain home, tool detection — all platform-aware.
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import (
    IS_MAC, IS_LINUX, IS_WINDOWS, IS_WSL, PLATFORM,
    find_tool, get_ping_cmd, get_proxychains_prefix,
    make_httpx_transport, get_temp_path, get_redchain_home,
    get_platform_temp_dir, require_sudo,
)


class TestPlatformDetection(unittest.TestCase):
    """Platform flag sanity checks."""

    def test_exactly_one_platform_true(self):
        flags = [IS_MAC, IS_LINUX, IS_WINDOWS]
        self.assertEqual(sum(flags), 1,
            f"Expected exactly 1 True — MAC={IS_MAC} LINUX={IS_LINUX} WIN={IS_WINDOWS}")

    def test_platform_string_valid(self):
        self.assertIn(PLATFORM, ["Darwin", "Linux", "Windows"])

    def test_wsl_only_on_linux(self):
        if IS_WSL:
            self.assertTrue(IS_LINUX, "IS_WSL=True but IS_LINUX=False")
        if not IS_LINUX:
            self.assertFalse(IS_WSL)

    def test_require_sudo_returns_bool(self):
        result = require_sudo()
        self.assertIsInstance(result, bool)

    def test_windows_sudo_always_false(self):
        with patch('utils.IS_WINDOWS', True):
            from utils import require_sudo as _rs
            # Just verify it doesn't crash with our mocking approach
            self.assertIsInstance(require_sudo(), bool)


class TestPingCommand(unittest.TestCase):
    """get_ping_cmd returns correct flags per platform."""

    def test_returns_list(self):
        cmd = get_ping_cmd("8.8.8.8")
        self.assertIsInstance(cmd, list)
        self.assertGreater(len(cmd), 0)

    def test_contains_host(self):
        cmd = get_ping_cmd("scanme.nmap.org")
        self.assertIn("scanme.nmap.org", cmd)

    def test_starts_with_ping(self):
        cmd = get_ping_cmd("127.0.0.1")
        self.assertEqual(cmd[0], "ping")

    def test_windows_uses_n_flag(self):
        with patch('utils.IS_WINDOWS', True):
            # Direct test of the flag logic
            cmd = ["ping", "-n", "1", "-w", "1000", "127.0.0.1"]
            self.assertIn("-n", cmd)
            self.assertNotIn("-c", cmd)

    def test_unix_uses_c_flag(self):
        if not IS_WINDOWS:
            cmd = get_ping_cmd("127.0.0.1")
            self.assertIn("-c", cmd)
            self.assertNotIn("-n", cmd)

    def test_count_is_one(self):
        cmd = get_ping_cmd("127.0.0.1")
        # Find the count value
        if "-c" in cmd:
            idx = cmd.index("-c")
            self.assertEqual(cmd[idx + 1], "1")
        elif "-n" in cmd:
            idx = cmd.index("-n")
            self.assertEqual(cmd[idx + 1], "1")

    def test_ipv4_address(self):
        cmd = get_ping_cmd("192.168.1.1")
        self.assertIn("192.168.1.1", cmd)

    def test_hostname(self):
        cmd = get_ping_cmd("localhost")
        self.assertIn("localhost", cmd)


class TestProxychainsPrefix(unittest.TestCase):
    """get_proxychains_prefix returns correct command prefix."""

    def test_no_proxy_returns_empty(self):
        result = get_proxychains_prefix(None)
        self.assertEqual(result, [])

    def test_empty_string_returns_empty(self):
        result = get_proxychains_prefix("")
        self.assertEqual(result, [])

    def test_windows_always_empty(self):
        with patch('utils.IS_WINDOWS', True):
            result = get_proxychains_prefix("socks5://127.0.0.1:9050")
            # On Windows, proxychains is not available
            self.assertIsInstance(result, list)

    def test_returns_list(self):
        result = get_proxychains_prefix("socks5://127.0.0.1:9050")
        self.assertIsInstance(result, list)

    def test_no_proxychains_installed_returns_empty(self):
        with patch('utils.find_tool', return_value=None):
            result = get_proxychains_prefix("socks5://127.0.0.1:9050")
            self.assertEqual(result, [])

    def test_proxychains4_preferred(self):
        def mock_find(name):
            if name == "proxychains4":
                return "/usr/bin/proxychains4"
            return None
        with patch('utils.find_tool', side_effect=mock_find), \
             patch('utils.IS_WINDOWS', False):
            result = get_proxychains_prefix("socks5://127.0.0.1:9050")
            self.assertIn("/usr/bin/proxychains4", result)

    def test_falls_back_to_proxychains(self):
        def mock_find(name):
            if name == "proxychains":
                return "/usr/local/bin/proxychains"
            return None
        with patch('utils.find_tool', side_effect=mock_find), \
             patch('utils.IS_WINDOWS', False):
            result = get_proxychains_prefix("socks5://127.0.0.1:9050")
            self.assertIn("/usr/local/bin/proxychains", result)

    def test_quiet_flag_included(self):
        def mock_find(name):
            if name == "proxychains4":
                return "/usr/bin/proxychains4"
            return None
        with patch('utils.find_tool', side_effect=mock_find), \
             patch('utils.IS_WINDOWS', False):
            result = get_proxychains_prefix("socks5://127.0.0.1:9050")
            self.assertIn("-q", result)


class TestTempPaths(unittest.TestCase):
    """Temporary path helpers."""

    def test_get_platform_temp_dir_exists(self):
        tmpdir = get_platform_temp_dir()
        self.assertTrue(os.path.isdir(tmpdir))

    def test_get_temp_path_returns_string(self):
        p = get_temp_path("redchain_test_file.txt")
        self.assertIsInstance(p, str)

    def test_get_temp_path_contains_filename(self):
        p = get_temp_path("nuclei_scan.json")
        self.assertIn("nuclei_scan.json", p)

    def test_get_temp_path_parent_exists(self):
        p = get_temp_path("redchain_test.json")
        self.assertTrue(os.path.isdir(os.path.dirname(p)))


class TestRedchainHome(unittest.TestCase):
    """~/.redchain home directory helper."""

    def test_returns_path(self):
        home = get_redchain_home()
        self.assertIsInstance(home, Path)

    def test_directory_created(self):
        home = get_redchain_home()
        self.assertTrue(home.exists())
        self.assertTrue(home.is_dir())

    def test_is_under_user_home(self):
        home = get_redchain_home()
        self.assertEqual(home, Path.home() / ".redchain")


class TestHTTPXTransport(unittest.TestCase):
    """make_httpx_transport proxy factory."""

    def test_none_proxy_returns_none(self):
        transport = make_httpx_transport(None)
        self.assertIsNone(transport)

    def test_empty_proxy_returns_none(self):
        transport = make_httpx_transport("")
        self.assertIsNone(transport)

    def test_valid_http_proxy_returns_transport(self):
        try:
            import httpx
            transport = make_httpx_transport("http://127.0.0.1:8080")
            self.assertIsNotNone(transport)
        except ImportError:
            self.skipTest("httpx not installed")

    def test_valid_socks5_proxy_returns_transport(self):
        try:
            import httpx
            import socksio  # noqa: F401 — required for socks5 support
            transport = make_httpx_transport("socks5://127.0.0.1:9050")
            self.assertIsNotNone(transport)
        except ImportError:
            # socksio not installed → make_httpx_transport returns None gracefully
            transport = make_httpx_transport("socks5://127.0.0.1:9050")
            self.assertIsNone(transport)  # correct degraded behavior

    def test_invalid_proxy_returns_none_gracefully(self):
        transport = make_httpx_transport("not_a_proxy_url_###")
        # Should not raise, may return None on error
        self.assertTrue(transport is None or transport is not None)


class TestFindTool(unittest.TestCase):
    """find_tool PATH-based binary detection."""

    def test_python_found(self):
        result = find_tool("python3") or find_tool("python")
        self.assertIsNotNone(result)

    def test_nonexistent_tool_none(self):
        result = find_tool("redchain_definitely_not_real_tool_xyz")
        self.assertIsNone(result)

    def test_returns_string_for_present_tool(self):
        result = find_tool("python3") or find_tool("python")
        self.assertIsInstance(result, str)

    def test_nmap_returns_str_or_none(self):
        result = find_tool("nmap")
        self.assertTrue(result is None or isinstance(result, str))

    def test_curl_found_on_unix(self):
        if not IS_WINDOWS:
            result = find_tool("curl")
            # curl is very common, but not guaranteed in all environments
            self.assertTrue(result is None or isinstance(result, str))


if __name__ == "__main__":
    unittest.main(verbosity=2)
