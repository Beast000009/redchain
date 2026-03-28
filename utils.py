"""
RedChain — Centralized utility functions and platform constants.
Eliminates duplication across cli.py, osint_agent.py, scanner_agent.py, webapp_agent.py.
"""

import os
import platform
import shutil
import tempfile
from pathlib import Path

# ── Platform Detection ────────────────────────────────────────────────────────

PLATFORM = platform.system()
IS_MAC = PLATFORM == "Darwin"
IS_LINUX = PLATFORM == "Linux"
IS_WINDOWS = PLATFORM == "Windows"


def _detect_wsl() -> bool:
    """Detect if running inside Windows Subsystem for Linux."""
    if not IS_LINUX:
        return False
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except (FileNotFoundError, PermissionError):
        return False


IS_WSL = _detect_wsl()


# ── Tool Helpers ──────────────────────────────────────────────────────────────

def find_tool(name: str) -> str | None:
    """Find a tool binary in the system PATH."""
    return shutil.which(name)


def require_sudo() -> bool:
    """Check if the current process has root/admin privileges."""
    if IS_WINDOWS:
        return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def get_platform_temp_dir() -> str:
    """Return a platform-appropriate temporary directory."""
    return tempfile.gettempdir()


def get_temp_path(filename: str) -> str:
    """Return a full path inside the system temp dir."""
    return os.path.join(tempfile.gettempdir(), filename)


def get_redchain_home() -> Path:
    """Return (and create) the ~/.redchain user data directory."""
    home = Path.home() / ".redchain"
    home.mkdir(parents=True, exist_ok=True)
    return home


def get_ping_cmd(host: str) -> list[str]:
    """Return a cross-platform single-ping command list."""
    if IS_WINDOWS:
        return ["ping", "-n", "1", "-w", "1000", host]
    else:
        return ["ping", "-c", "1", "-W", "1", host]


def get_proxychains_prefix(proxy: str | None) -> list[str]:
    """
    Return a command prefix to wrap subprocess calls through a proxy.
    Uses proxychains4 (Linux), proxychains (macOS), or empty list (Windows/no proxy).
    """
    if not proxy:
        return []
    if IS_WINDOWS:
        return []  # proxychains not available on Windows natively
    pc4 = find_tool("proxychains4")
    if pc4:
        return [pc4, "-q"]
    pc = find_tool("proxychains")
    if pc:
        return [pc, "-q"]
    return []


def make_httpx_transport(proxy: str | None):
    """
    Return an httpx transport configured for the given proxy URL.
    Supports http://, https://, and socks5:// proxies.
    Returns None if no proxy is set or if the required extras are missing.
    Note: socks5:// requires `pip install httpx[socks]`
    """
    if not proxy:
        return None
    try:
        import httpx
        if proxy.startswith("socks"):
            # Requires httpx[socks] — test if socksio is available
            try:
                import socksio  # noqa: F401
                return httpx.AsyncHTTPTransport(proxy=proxy)
            except ImportError:
                # Fall back to no transport (direct) rather than crashing
                return None
        return httpx.AsyncHTTPTransport(proxy=proxy)
    except Exception:
        return None


def setup_platform_env() -> None:
    """Set up platform-specific environment variables."""
    if IS_MAC:
        # macOS Homebrew Library Path Fallback (Essential for WeasyPrint/Pango)
        os.environ['DYLD_FALLBACK_LIBRARY_PATH'] = (
            '/opt/homebrew/lib:' + os.environ.get('DYLD_FALLBACK_LIBRARY_PATH', '')
        )
