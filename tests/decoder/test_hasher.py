"""
Unit tests for hash generation and binary analysis.

Tests the Hasher and BinaryAnalyzer classes for correctness.
"""

import pytest
from src.oasis.decoder import Hasher, BinaryAnalyzer, HashAlgorithm


class TestHasher:
    """Tests for the Hasher class."""
    
    def test_md5_hash(self):
        """Test MD5 hash generation."""
        hasher = Hasher()
        result = hasher.hash_data("hello", HashAlgorithm.MD5)
        
        assert result.algorithm == HashAlgorithm.MD5
        assert result.hash_hex == "5d41402abc4b2a76b9719d911017c592"
        assert len(result.hash_bytes) == 16
    
    def test_sha1_hash(self):
        """Test SHA1 hash generation."""
        hasher = Hasher()
        result = hasher.hash_data("hello", HashAlgorithm.SHA1)
        
        assert result.algorithm == HashAlgorithm.SHA1
        assert result.hash_hex == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        assert len(result.hash_bytes) == 20
    
    def test_sha256_hash(self):
        """Test SHA256 hash generation."""
        hasher = Hasher()
        result = hasher.hash_data("hello", HashAlgorithm.SHA256)
        
        assert result.algorithm == HashAlgorithm.SHA256
        assert result.hash_hex == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        assert len(result.hash_bytes) == 32
    
    def test_hash_bytes_input(self):
        """Test hashing with bytes input."""
        hasher = Hasher()
        result = hasher.hash_data(b"hello", HashAlgorithm.SHA256)
        
        assert result.hash_hex == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    
    def test_hmac_hash(self):
        """Test HMAC hash generation."""
        hasher = Hasher()
        result = hasher.hmac_hash("message", "secret_key", HashAlgorithm.SHA256)
        
        assert result.algorithm == HashAlgorithm.SHA256
        assert len(result.hash_hex) == 64  # SHA256 produces 32 bytes = 64 hex chars
        assert len(result.hash_bytes) == 32
    
    def test_hmac_with_bytes(self):
        """Test HMAC with bytes input."""
        hasher = Hasher()
        result = hasher.hmac_hash(b"message", b"secret_key", HashAlgorithm.SHA256)
        
        assert len(result.hash_hex) == 64
    
    def test_verify_hash_success(self):
        """Test hash verification with correct hash."""
        hasher = Hasher()
        data = "test data"
        expected = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        
        assert hasher.verify_hash(data, expected, HashAlgorithm.SHA256)
    
    def test_verify_hash_failure(self):
        """Test hash verification with incorrect hash."""
        hasher = Hasher()
        data = "test data"
        wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        
        assert not hasher.verify_hash(data, wrong_hash, HashAlgorithm.SHA256)
    
    def test_compare_hashes_case_insensitive(self):
        """Test hash comparison is case-insensitive."""
        hasher = Hasher()
        hash1 = "ABCDEF123456"
        hash2 = "abcdef123456"
        
        assert hasher.compare_hashes(hash1, hash2)
    
    def test_compare_hashes_different(self):
        """Test hash comparison with different hashes."""
        hasher = Hasher()
        hash1 = "abc123"
        hash2 = "def456"
        
        assert not hasher.compare_hashes(hash1, hash2)


class TestBinaryAnalyzer:
    """Tests for the BinaryAnalyzer class."""
    
    def test_hex_dump_basic(self):
        """Test basic hex dump generation."""
        analyzer = BinaryAnalyzer()
        data = b"Hello, World!"
        
        dump = analyzer.hex_dump(data)
        
        assert "48 65 6c 6c 6f" in dump  # "Hello" in hex
        assert "Hello, World!" in dump  # ASCII representation
        assert "00000000" in dump  # Offset
    
    def test_hex_dump_no_offset(self):
        """Test hex dump without offset."""
        analyzer = BinaryAnalyzer()
        data = b"test"
        
        dump = analyzer.hex_dump(data, show_offset=False)
        
        assert "00000000" not in dump
        assert "74 65 73 74" in dump  # "test" in hex
    
    def test_hex_dump_no_ascii(self):
        """Test hex dump without ASCII representation."""
        analyzer = BinaryAnalyzer()
        data = b"test"
        
        dump = analyzer.hex_dump(data, show_ascii=False)
        
        assert "|test|" not in dump
        assert "74 65 73 74" in dump
    
    def test_hex_dump_custom_width(self):
        """Test hex dump with custom bytes per line."""
        analyzer = BinaryAnalyzer()
        data = b"0123456789ABCDEF"
        
        dump = analyzer.hex_dump(data, bytes_per_line=8)
        
        lines = dump.split('\n')
        assert len(lines) == 2  # 16 bytes / 8 per line = 2 lines
    
    def test_analyze_binary_printable(self):
        """Test binary analysis with printable data."""
        analyzer = BinaryAnalyzer()
        data = b"Hello, World!"
        
        analysis = analyzer.analyze_binary(data)
        
        assert analysis['size'] == 13
        assert analysis['printable_ratio'] == 1.0
        assert analysis['null_bytes'] == 0
        assert analysis['entropy'] > 0
        assert not analysis['has_high_entropy']
    
    def test_analyze_binary_with_nulls(self):
        """Test binary analysis with null bytes."""
        analyzer = BinaryAnalyzer()
        data = b"test\x00\x00data"
        
        analysis = analyzer.analyze_binary(data)
        
        assert analysis['null_bytes'] == 2
        assert analysis['printable_ratio'] < 1.0
    
    def test_analyze_binary_empty(self):
        """Test binary analysis with empty data."""
        analyzer = BinaryAnalyzer()
        data = b""
        
        analysis = analyzer.analyze_binary(data)
        
        assert analysis['size'] == 0
        assert analysis['printable_ratio'] == 0.0
        assert analysis['null_bytes'] == 0
        assert analysis['entropy'] == 0.0
    
    def test_find_strings_basic(self):
        """Test string extraction from binary data."""
        analyzer = BinaryAnalyzer()
        data = b"Hello\x00World\x00Test"
        
        strings = analyzer.find_strings(data, min_length=4)
        
        assert "Hello" in strings
        assert "World" in strings
        assert "Test" in strings
    
    def test_find_strings_min_length(self):
        """Test string extraction with minimum length filter."""
        analyzer = BinaryAnalyzer()
        data = b"Hi\x00Hello\x00A\x00Test"
        
        strings = analyzer.find_strings(data, min_length=4)
        
        assert "Hello" in strings
        assert "Test" in strings
        assert "Hi" not in strings  # Too short
        assert "A" not in strings  # Too short
    
    def test_compare_binary_identical(self):
        """Test binary comparison with identical data."""
        analyzer = BinaryAnalyzer()
        data1 = b"test data"
        data2 = b"test data"
        
        result = analyzer.compare_binary(data1, data2)
        
        assert result['identical']
        assert result['size_diff'] == 0
        assert len(result['diff_positions']) == 0
        assert result['similarity_ratio'] == 1.0
    
    def test_compare_binary_different(self):
        """Test binary comparison with different data."""
        analyzer = BinaryAnalyzer()
        data1 = b"test data"
        data2 = b"test info"
        
        result = analyzer.compare_binary(data1, data2)
        
        assert not result['identical']
        assert result['size_diff'] == 0
        assert len(result['diff_positions']) > 0
        assert result['similarity_ratio'] < 1.0
    
    def test_compare_binary_different_sizes(self):
        """Test binary comparison with different sizes."""
        analyzer = BinaryAnalyzer()
        data1 = b"short"
        data2 = b"much longer data"
        
        result = analyzer.compare_binary(data1, data2)
        
        assert not result['identical']
        assert result['size_diff'] == 11  # 16 - 5
        assert len(result['diff_positions']) > 0
        assert result['similarity_ratio'] < 1.0
