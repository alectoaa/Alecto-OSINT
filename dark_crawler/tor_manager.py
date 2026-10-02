"""
dark_crawler/tor_manager.py
-----------------------------
Tor Expert Bundle'i otomatik indirir, kurar ve baslatir.
server.py baslangicinda cagrilir.
"""

import asyncio
import logging
import os
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

# Tor Expert Bundle Windows x86_64
TOR_DOWNLOAD_URL = (
    "https://archive.torproject.org/tor-package-archive/torbrowser/"
    "13.5.1/tor-expert-bundle-windows-x86_64-13.5.1.tar.gz"
)
TOR_DIR      = Path(os.getenv("TOR_DIR", "C:/tor")).expanduser()
TOR_EXE      = TOR_DIR / "tor" / "tor.exe"
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", "9051"))

_tor_process: subprocess.Popen | None = None


def is_tor_running() -> bool:
    """Port 9050 dinleniyor mu kontrol eder."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", TOR_SOCKS_PORT), timeout=2):
            return True
    except OSError:
        return False


def download_tor() -> bool:
    """Tor Expert Bundle'i indirir ve C:/tor/ klasorune cikartr."""
    if TOR_EXE.exists():
        logger.info("[TorManager] tor.exe zaten mevcut.")
        return True

    archive_path = TOR_DIR / "tor-bundle.tar.gz"
    TOR_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("[TorManager] Tor Expert Bundle indiriliyor...")
    try:
        urllib.request.urlretrieve(TOR_DOWNLOAD_URL, archive_path)
        logger.info("[TorManager] Indirme tamamlandi, cikariliyor...")
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(TOR_DIR)
        archive_path.unlink(missing_ok=True)
        logger.info(f"[TorManager] Tor kuruldu: {TOR_EXE}")
        return TOR_EXE.exists()
    except Exception as e:
        logger.error(f"[TorManager] Indirme/kurulum hatasi: {e}")
        return False


def start_tor() -> bool:
    """tor.exe'yi arka planda baslatir."""
    global _tor_process

    if is_tor_running():
        logger.info("[TorManager] Tor zaten calisiyor.")
        return True

    if not TOR_EXE.exists():
        logger.info("[TorManager] tor.exe bulunamadi, indiriliyor...")
        if not download_tor():
            return False

    try:
        _tor_process = subprocess.Popen(
            [str(TOR_EXE)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        logger.info("[TorManager] tor.exe baslatildi, hazir olana kadar bekleniyor...")

        # Maks 60 saniye bekle — Tor ağ devresi kurmak 15-20s sürebilir
        for i in range(60):
            if is_tor_running():
                logger.info(f"[TorManager] Tor hazir ({i+1}s)")
                return True
            time.sleep(1)

        logger.error("[TorManager] Tor 60 saniye icinde hazir olmadi.")
        return False

    except Exception as e:
        logger.error(f"[TorManager] Tor baslatma hatasi: {e}")
        return False


def stop_tor():
    """Tor process'ini durdurur."""
    global _tor_process
    if _tor_process:
        _tor_process.terminate()
        _tor_process = None
        logger.info("[TorManager] Tor durduruldu.")


def renew_tor_circuit() -> bool:
    """Tor control port üzerinden yeni circuit (NEWNYM) sinyali yollar."""
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=TOR_CONTROL_PORT) as ctrl:
            ctrl.authenticate()
            ctrl.signal(Signal.NEWNYM)
            time.sleep(1.5)
        return True
    except Exception as exc:
        logger.debug(f"[TorManager] NEWNYM hatasi: {type(exc).__name__}: {exc}")
        return False


async def ensure_tor() -> bool:
    """
    Async wrapper — server.py'den cagrilir.
    Tor calismiyorsa indirir ve baslatir.
    """
    if is_tor_running():
        return True

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, start_tor)
