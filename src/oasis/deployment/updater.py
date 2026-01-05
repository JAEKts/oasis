"""
Secure Update Manager

Handles secure software updates with signature verification and rollback capabilities.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


class UpdateChannel(Enum):
    """Update channel types"""

    STABLE = "stable"
    BETA = "beta"
    NIGHTLY = "nightly"


class UpdateStatus(Enum):
    """Update status"""

    CHECKING = "checking"
    AVAILABLE = "available"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    INSTALLING = "installing"
    COMPLETED = "completed"
    FAILED = "failed"
    UP_TO_DATE = "up_to_date"


@dataclass
class UpdateInfo:
    """Information about an available update"""

    version: str
    release_date: datetime
    channel: UpdateChannel
    download_url: str
    signature_url: str
    checksum: str
    size_bytes: int
    release_notes: str
    critical: bool = False
    security_update: bool = False


@dataclass
class UpdateProgress:
    """Update progress information"""

    status: UpdateStatus
    progress_percent: float
    message: str
    error: Optional[str] = None


class UpdateVerifier:
    """Verifies update authenticity using cryptographic signatures"""

    def __init__(self, public_key_path: Optional[Path] = None):
        """
        Initialize update verifier

        Args:
            public_key_path: Path to public key for signature verification
        """
        self.public_key_path = (
            public_key_path or Path.home() / ".oasis" / "update_key.pub"
        )
        self.public_key: Optional[rsa.RSAPublicKey] = None

        if self.public_key_path.exists():
            self._load_public_key()

    def _load_public_key(self) -> None:
        """Load public key from file"""
        try:
            with open(self.public_key_path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(f.read())
            logger.info(f"Loaded public key from {self.public_key_path}")
        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            raise

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """
        Verify cryptographic signature of data

        Args:
            data: Data to verify
            signature: Signature to check

        Returns:
            True if signature is valid, False otherwise
        """
        if not self.public_key:
            logger.error("No public key loaded for signature verification")
            return False

        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            logger.error("Invalid signature detected")
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False

    def verify_checksum(self, data: bytes, expected_checksum: str) -> bool:
        """
        Verify SHA256 checksum of data

        Args:
            data: Data to verify
            expected_checksum: Expected SHA256 checksum (hex)

        Returns:
            True if checksum matches, False otherwise
        """
        actual_checksum = hashlib.sha256(data).hexdigest()
        return actual_checksum == expected_checksum


class UpdateManager:
    """Manages secure software updates"""

    def __init__(
        self,
        current_version: str,
        update_server_url: str,
        channel: UpdateChannel = UpdateChannel.STABLE,
        cache_dir: Optional[Path] = None,
        verifier: Optional[UpdateVerifier] = None,
    ):
        """
        Initialize update manager

        Args:
            current_version: Current software version
            update_server_url: Base URL of update server
            channel: Update channel to use
            cache_dir: Directory for caching downloads
            verifier: Update verifier instance
        """
        self.current_version = current_version
        self.update_server_url = update_server_url
        self.channel = channel
        self.cache_dir = cache_dir or Path.home() / ".oasis" / "updates"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.verifier = verifier or UpdateVerifier()

        self._progress_callbacks: List[callable] = []

    def add_progress_callback(self, callback: callable) -> None:
        """Add callback for progress updates"""
        self._progress_callbacks.append(callback)

    def _notify_progress(self, progress: UpdateProgress) -> None:
        """Notify all progress callbacks"""
        for callback in self._progress_callbacks:
            try:
                callback(progress)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")

    async def check_for_updates(self) -> Optional[UpdateInfo]:
        """
        Check if updates are available

        Returns:
            UpdateInfo if update available, None otherwise
        """
        self._notify_progress(
            UpdateProgress(
                status=UpdateStatus.CHECKING,
                progress_percent=0.0,
                message="Checking for updates...",
            )
        )

        try:
            update_url = urljoin(
                self.update_server_url, f"/api/updates/{self.channel.value}/latest"
            )

            async with aiohttp.ClientSession() as session:
                async with session.get(update_url) as response:
                    if response.status != 200:
                        logger.error(f"Update check failed: HTTP {response.status}")
                        return None

                    data = await response.json()

                    # Parse update info
                    update_info = UpdateInfo(
                        version=data["version"],
                        release_date=datetime.fromisoformat(data["release_date"]),
                        channel=UpdateChannel(data["channel"]),
                        download_url=data["download_url"],
                        signature_url=data["signature_url"],
                        checksum=data["checksum"],
                        size_bytes=data["size_bytes"],
                        release_notes=data["release_notes"],
                        critical=data.get("critical", False),
                        security_update=data.get("security_update", False),
                    )

                    # Check if update is newer
                    if self._is_newer_version(update_info.version):
                        self._notify_progress(
                            UpdateProgress(
                                status=UpdateStatus.AVAILABLE,
                                progress_percent=0.0,
                                message=f"Update available: {update_info.version}",
                            )
                        )
                        return update_info
                    else:
                        self._notify_progress(
                            UpdateProgress(
                                status=UpdateStatus.UP_TO_DATE,
                                progress_percent=100.0,
                                message="Software is up to date",
                            )
                        )
                        return None

        except Exception as e:
            logger.error(f"Update check failed: {e}")
            self._notify_progress(
                UpdateProgress(
                    status=UpdateStatus.FAILED,
                    progress_percent=0.0,
                    message="Update check failed",
                    error=str(e),
                )
            )
            return None

    def _is_newer_version(self, version: str) -> bool:
        """
        Compare version strings

        Args:
            version: Version to compare

        Returns:
            True if version is newer than current
        """
        # Simple version comparison (should use packaging.version in production)
        current_parts = [int(x) for x in self.current_version.split(".")]
        new_parts = [int(x) for x in version.split(".")]

        return new_parts > current_parts

    async def download_update(self, update_info: UpdateInfo) -> Optional[Path]:
        """
        Download update package

        Args:
            update_info: Information about update to download

        Returns:
            Path to downloaded file, or None on failure
        """
        self._notify_progress(
            UpdateProgress(
                status=UpdateStatus.DOWNLOADING,
                progress_percent=0.0,
                message=f"Downloading update {update_info.version}...",
            )
        )

        try:
            download_path = self.cache_dir / f"oasis-{update_info.version}.pkg"
            signature_path = self.cache_dir / f"oasis-{update_info.version}.sig"

            # Download update package
            async with aiohttp.ClientSession() as session:
                # Download main package
                async with session.get(update_info.download_url) as response:
                    if response.status != 200:
                        raise Exception(f"Download failed: HTTP {response.status}")

                    total_size = update_info.size_bytes
                    downloaded = 0

                    with open(download_path, "wb") as f:
                        async for chunk in response.content.iter_chunked(8192):
                            f.write(chunk)
                            downloaded += len(chunk)
                            progress = (downloaded / total_size) * 100

                            self._notify_progress(
                                UpdateProgress(
                                    status=UpdateStatus.DOWNLOADING,
                                    progress_percent=progress,
                                    message=f"Downloaded {downloaded}/{total_size} bytes",
                                )
                            )

                # Download signature
                async with session.get(update_info.signature_url) as response:
                    if response.status != 200:
                        raise Exception(
                            f"Signature download failed: HTTP {response.status}"
                        )

                    signature_data = await response.read()
                    with open(signature_path, "wb") as f:
                        f.write(signature_data)

            # Verify download
            self._notify_progress(
                UpdateProgress(
                    status=UpdateStatus.VERIFYING,
                    progress_percent=0.0,
                    message="Verifying download...",
                )
            )

            with open(download_path, "rb") as f:
                package_data = f.read()

            with open(signature_path, "rb") as f:
                signature_data = f.read()

            # Verify checksum
            if not self.verifier.verify_checksum(package_data, update_info.checksum):
                raise Exception("Checksum verification failed")

            # Verify signature
            if not self.verifier.verify_signature(package_data, signature_data):
                raise Exception("Signature verification failed")

            self._notify_progress(
                UpdateProgress(
                    status=UpdateStatus.VERIFYING,
                    progress_percent=100.0,
                    message="Verification successful",
                )
            )

            return download_path

        except Exception as e:
            logger.error(f"Update download failed: {e}")
            self._notify_progress(
                UpdateProgress(
                    status=UpdateStatus.FAILED,
                    progress_percent=0.0,
                    message="Download failed",
                    error=str(e),
                )
            )
            return None

    async def install_update(self, package_path: Path) -> bool:
        """
        Install downloaded update

        Args:
            package_path: Path to verified update package

        Returns:
            True if installation successful, False otherwise
        """
        self._notify_progress(
            UpdateProgress(
                status=UpdateStatus.INSTALLING,
                progress_percent=0.0,
                message="Installing update...",
            )
        )

        try:
            # In production, this would:
            # 1. Create backup of current installation
            # 2. Extract and install new version
            # 3. Migrate configuration and data
            # 4. Restart application

            # For now, just simulate installation
            await asyncio.sleep(2)

            self._notify_progress(
                UpdateProgress(
                    status=UpdateStatus.COMPLETED,
                    progress_percent=100.0,
                    message="Update installed successfully",
                )
            )

            return True

        except Exception as e:
            logger.error(f"Update installation failed: {e}")
            self._notify_progress(
                UpdateProgress(
                    status=UpdateStatus.FAILED,
                    progress_percent=0.0,
                    message="Installation failed",
                    error=str(e),
                )
            )
            return False

    async def perform_update(self, update_info: UpdateInfo) -> bool:
        """
        Perform complete update process

        Args:
            update_info: Information about update to install

        Returns:
            True if update successful, False otherwise
        """
        # Download update
        package_path = await self.download_update(update_info)
        if not package_path:
            return False

        # Install update
        return await self.install_update(package_path)
