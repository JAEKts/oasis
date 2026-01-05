"""
Deployment Packager

Creates deployment packages for multiple platforms (Windows, macOS, Linux).
"""

import asyncio
import logging
import os
import platform
import shutil
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class Platform(Enum):
    """Supported platforms"""

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"


class PackageFormat(Enum):
    """Package formats"""

    ZIP = "zip"
    TAR_GZ = "tar.gz"
    DEB = "deb"
    RPM = "rpm"
    DMG = "dmg"
    MSI = "msi"
    APPIMAGE = "appimage"


@dataclass
class PlatformPackage:
    """Platform-specific package information"""

    platform: Platform
    format: PackageFormat
    path: Path
    version: str
    size_bytes: int
    checksum: str


class DeploymentPackager:
    """Creates deployment packages for multiple platforms"""

    def __init__(
        self, project_root: Path, version: str, output_dir: Optional[Path] = None
    ):
        """
        Initialize deployment packager

        Args:
            project_root: Root directory of project
            version: Version to package
            output_dir: Output directory for packages
        """
        self.project_root = project_root
        self.version = version
        self.output_dir = output_dir or project_root / "dist"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.build_dir = project_root / "build"
        self.build_dir.mkdir(parents=True, exist_ok=True)

    async def package_all_platforms(self) -> List[PlatformPackage]:
        """
        Create packages for all supported platforms

        Returns:
            List of created packages
        """
        packages = []

        # Package for each platform
        for platform_type in Platform:
            try:
                package = await self.package_platform(platform_type)
                if package:
                    packages.append(package)
            except Exception as e:
                logger.error(f"Failed to package for {platform_type.value}: {e}")

        return packages

    async def package_platform(
        self, platform_type: Platform
    ) -> Optional[PlatformPackage]:
        """
        Create package for specific platform

        Args:
            platform_type: Platform to package for

        Returns:
            Created package, or None on failure
        """
        logger.info(f"Creating package for {platform_type.value}")

        try:
            if platform_type == Platform.WINDOWS:
                return await self._package_windows()
            elif platform_type == Platform.MACOS:
                return await self._package_macos()
            elif platform_type == Platform.LINUX:
                return await self._package_linux()
            else:
                logger.error(f"Unsupported platform: {platform_type}")
                return None

        except Exception as e:
            logger.error(f"Packaging failed for {platform_type.value}: {e}")
            return None

    async def _package_windows(self) -> Optional[PlatformPackage]:
        """Create Windows package (MSI/ZIP)"""
        logger.info("Creating Windows package")

        # Create ZIP package
        package_name = f"oasis-{self.version}-windows-x64.zip"
        package_path = self.output_dir / package_name

        # Prepare build directory
        win_build_dir = self.build_dir / "windows"
        win_build_dir.mkdir(parents=True, exist_ok=True)

        # Copy application files
        await self._copy_application_files(win_build_dir)

        # Add Windows-specific files
        await self._add_windows_files(win_build_dir)

        # Create ZIP archive
        with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(win_build_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(win_build_dir)
                    zipf.write(file_path, arcname)

        # Calculate checksum
        checksum = await self._calculate_checksum(package_path)

        package = PlatformPackage(
            platform=Platform.WINDOWS,
            format=PackageFormat.ZIP,
            path=package_path,
            version=self.version,
            size_bytes=package_path.stat().st_size,
            checksum=checksum,
        )

        logger.info(f"Created Windows package: {package_path}")
        return package

    async def _package_macos(self) -> Optional[PlatformPackage]:
        """Create macOS package (DMG)"""
        logger.info("Creating macOS package")

        # Create TAR.GZ package (DMG creation requires macOS)
        package_name = f"oasis-{self.version}-macos-x64.tar.gz"
        package_path = self.output_dir / package_name

        # Prepare build directory
        mac_build_dir = self.build_dir / "macos"
        mac_build_dir.mkdir(parents=True, exist_ok=True)

        # Copy application files
        await self._copy_application_files(mac_build_dir)

        # Add macOS-specific files
        await self._add_macos_files(mac_build_dir)

        # Create TAR.GZ archive
        with tarfile.open(package_path, "w:gz") as tar:
            tar.add(mac_build_dir, arcname=f"oasis-{self.version}")

        # Calculate checksum
        checksum = await self._calculate_checksum(package_path)

        package = PlatformPackage(
            platform=Platform.MACOS,
            format=PackageFormat.TAR_GZ,
            path=package_path,
            version=self.version,
            size_bytes=package_path.stat().st_size,
            checksum=checksum,
        )

        logger.info(f"Created macOS package: {package_path}")
        return package

    async def _package_linux(self) -> Optional[PlatformPackage]:
        """Create Linux package (TAR.GZ/DEB/RPM)"""
        logger.info("Creating Linux package")

        # Create TAR.GZ package
        package_name = f"oasis-{self.version}-linux-x64.tar.gz"
        package_path = self.output_dir / package_name

        # Prepare build directory
        linux_build_dir = self.build_dir / "linux"
        linux_build_dir.mkdir(parents=True, exist_ok=True)

        # Copy application files
        await self._copy_application_files(linux_build_dir)

        # Add Linux-specific files
        await self._add_linux_files(linux_build_dir)

        # Create TAR.GZ archive
        with tarfile.open(package_path, "w:gz") as tar:
            tar.add(linux_build_dir, arcname=f"oasis-{self.version}")

        # Calculate checksum
        checksum = await self._calculate_checksum(package_path)

        package = PlatformPackage(
            platform=Platform.LINUX,
            format=PackageFormat.TAR_GZ,
            path=package_path,
            version=self.version,
            size_bytes=package_path.stat().st_size,
            checksum=checksum,
        )

        logger.info(f"Created Linux package: {package_path}")
        return package

    async def _copy_application_files(self, target_dir: Path) -> None:
        """
        Copy application files to build directory

        Args:
            target_dir: Target directory
        """
        # Copy source files
        src_dir = self.project_root / "src"
        if src_dir.exists():
            shutil.copytree(src_dir, target_dir / "src", dirs_exist_ok=True)

        # Copy configuration files
        for config_file in [
            "pyproject.toml",
            "requirements.txt",
            "README.md",
            "LICENSE",
        ]:
            config_path = self.project_root / config_file
            if config_path.exists():
                shutil.copy2(config_path, target_dir / config_file)

        # Copy examples
        examples_dir = self.project_root / "examples"
        if examples_dir.exists():
            shutil.copytree(examples_dir, target_dir / "examples", dirs_exist_ok=True)

    async def _add_windows_files(self, target_dir: Path) -> None:
        """
        Add Windows-specific files

        Args:
            target_dir: Target directory
        """
        # Create launcher script
        launcher_script = target_dir / "oasis.bat"
        with open(launcher_script, "w") as f:
            f.write("@echo off\n")
            f.write("python -m oasis.main %*\n")

        # Create installation script
        install_script = target_dir / "install.bat"
        with open(install_script, "w") as f:
            f.write("@echo off\n")
            f.write("echo Installing OASIS...\n")
            f.write("pip install -r requirements.txt\n")
            f.write("echo Installation complete!\n")

    async def _add_macos_files(self, target_dir: Path) -> None:
        """
        Add macOS-specific files

        Args:
            target_dir: Target directory
        """
        # Create launcher script
        launcher_script = target_dir / "oasis.sh"
        with open(launcher_script, "w") as f:
            f.write("#!/bin/bash\n")
            f.write('python3 -m oasis.main "$@"\n')
        launcher_script.chmod(0o755)

        # Create installation script
        install_script = target_dir / "install.sh"
        with open(install_script, "w") as f:
            f.write("#!/bin/bash\n")
            f.write("echo 'Installing OASIS...'\n")
            f.write("pip3 install -r requirements.txt\n")
            f.write("echo 'Installation complete!'\n")
        install_script.chmod(0o755)

    async def _add_linux_files(self, target_dir: Path) -> None:
        """
        Add Linux-specific files

        Args:
            target_dir: Target directory
        """
        # Create launcher script
        launcher_script = target_dir / "oasis.sh"
        with open(launcher_script, "w") as f:
            f.write("#!/bin/bash\n")
            f.write('python3 -m oasis.main "$@"\n')
        launcher_script.chmod(0o755)

        # Create installation script
        install_script = target_dir / "install.sh"
        with open(install_script, "w") as f:
            f.write("#!/bin/bash\n")
            f.write("echo 'Installing OASIS...'\n")
            f.write("pip3 install -r requirements.txt\n")
            f.write("echo 'Installation complete!'\n")
        install_script.chmod(0o755)

        # Create systemd service file
        service_file = target_dir / "oasis.service"
        with open(service_file, "w") as f:
            f.write("[Unit]\n")
            f.write("Description=OASIS Penetration Testing Suite\n")
            f.write("After=network.target\n\n")
            f.write("[Service]\n")
            f.write("Type=simple\n")
            f.write("ExecStart=/usr/bin/python3 -m oasis.main\n")
            f.write("Restart=on-failure\n\n")
            f.write("[Install]\n")
            f.write("WantedBy=multi-user.target\n")

    async def _calculate_checksum(self, file_path: Path) -> str:
        """
        Calculate SHA256 checksum of file

        Args:
            file_path: Path to file

        Returns:
            SHA256 checksum (hex)
        """
        import hashlib

        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    def generate_release_notes(self, packages: List[PlatformPackage]) -> str:
        """
        Generate release notes for packages

        Args:
            packages: List of created packages

        Returns:
            Release notes text
        """
        notes = f"# OASIS {self.version} Release\n\n"
        notes += "## Packages\n\n"

        for package in packages:
            notes += f"### {package.platform.value.title()}\n"
            notes += f"- Format: {package.format.value}\n"
            notes += f"- Size: {package.size_bytes / (1024 * 1024):.2f} MB\n"
            notes += f"- SHA256: `{package.checksum}`\n\n"

        notes += "## Installation\n\n"
        notes += "Please refer to the [installation guide](docs/user/INSTALLATION.md) for platform-specific instructions.\n\n"
        notes += "## Verification\n\n"
        notes += "Verify package integrity using the provided SHA256 checksums:\n\n"
        notes += "```bash\n"
        notes += "sha256sum oasis-*.tar.gz\n"
        notes += "```\n"

        return notes
