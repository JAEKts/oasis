#!/usr/bin/env python3
"""
Demo script showing the OASIS decoder utilities in action.

This demonstrates encoding/decoding, hash generation, and binary analysis
capabilities for penetration testing workflows.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.oasis.decoder import (
    DataTransformer,
    EncodingChain,
    EncodingType,
    Hasher,
    BinaryAnalyzer,
    HashAlgorithm,
)


def demo_basic_encoding():
    """Demonstrate basic encoding and decoding operations."""
    print("=" * 60)
    print("Basic Encoding/Decoding Demo")
    print("=" * 60)
    
    transformer = DataTransformer()
    original = "Hello, World! <script>alert('XSS')</script>"
    
    # URL encoding
    url_encoded = transformer.encode(original, EncodingType.URL)
    print(f"\nOriginal: {original}")
    print(f"URL Encoded: {url_encoded}")
    print(f"URL Decoded: {transformer.decode(url_encoded, EncodingType.URL)}")
    
    # HTML encoding
    html_encoded = transformer.encode(original, EncodingType.HTML)
    print(f"\nHTML Encoded: {html_encoded}")
    print(f"HTML Decoded: {transformer.decode(html_encoded, EncodingType.HTML)}")
    
    # Base64 encoding
    base64_encoded = transformer.encode(original, EncodingType.BASE64)
    print(f"\nBase64 Encoded: {base64_encoded}")
    print(f"Base64 Decoded: {transformer.decode(base64_encoded, EncodingType.BASE64)}")
    
    # Hex encoding
    hex_encoded = transformer.encode(original, EncodingType.HEX)
    print(f"\nHex Encoded: {hex_encoded}")
    print(f"Hex Decoded: {transformer.decode(hex_encoded, EncodingType.HEX)}")


def demo_encoding_chain():
    """Demonstrate chained encoding operations."""
    print("\n" + "=" * 60)
    print("Encoding Chain Demo")
    print("=" * 60)
    
    chain = EncodingChain()
    chain.add_step(EncodingType.HTML).add_step(EncodingType.URL).add_step(EncodingType.BASE64)
    
    original = "<script>alert('test')</script>"
    print(f"\nOriginal: {original}")
    print(f"Encoding chain: HTML -> URL -> Base64")
    
    # Encode through the chain
    encoded = chain.execute(original)
    print(f"Encoded: {encoded}")
    
    # Decode through the chain (reverse order)
    decoded = chain.reverse(encoded)
    print(f"Decoded: {decoded}")
    print(f"Match: {decoded == original}")


def demo_auto_decode():
    """Demonstrate automatic encoding detection."""
    print("\n" + "=" * 60)
    print("Auto-Decode Demo")
    print("=" * 60)
    
    transformer = DataTransformer()
    
    # Test various encoded strings
    test_cases = [
        ("Hello%20World%21", "URL encoded"),
        ("SGVsbG8gV29ybGQh", "Base64 encoded"),
        ("48656c6c6f20576f726c6421", "Hex encoded"),
        ("&lt;script&gt;alert(&apos;XSS&apos;)&lt;/script&gt;", "HTML encoded"),
    ]
    
    for encoded_data, description in test_cases:
        print(f"\n{description}: {encoded_data}")
        results = transformer.auto_decode(encoded_data)
        
        if results:
            print("Detection results (sorted by confidence):")
            for result in results[:3]:  # Show top 3
                if result.error is None:
                    print(f"  - {result.encoding_type.value}: {result.decoded_data} "
                          f"(confidence: {result.confidence:.2f})")


def demo_hashing():
    """Demonstrate hash generation capabilities."""
    print("\n" + "=" * 60)
    print("Hash Generation Demo")
    print("=" * 60)
    
    hasher = Hasher()
    data = "password123"
    
    print(f"\nData: {data}")
    
    # Generate various hashes
    for algorithm in [HashAlgorithm.MD5, HashAlgorithm.SHA1, HashAlgorithm.SHA256]:
        result = hasher.hash_data(data, algorithm)
        print(f"{algorithm.value.upper()}: {result.hash_hex}")
    
    # HMAC example
    print("\nHMAC Example:")
    secret_key = "my_secret_key"
    message = "Important message"
    hmac_result = hasher.hmac_hash(message, secret_key, HashAlgorithm.SHA256)
    print(f"Message: {message}")
    print(f"Key: {secret_key}")
    print(f"HMAC-SHA256: {hmac_result.hash_hex}")
    
    # Hash verification
    print("\nHash Verification:")
    expected_hash = hasher.hash_data("test", HashAlgorithm.SHA256).hash_hex
    print(f"Verifying 'test' against {expected_hash[:32]}...")
    print(f"Valid: {hasher.verify_hash('test', expected_hash, HashAlgorithm.SHA256)}")
    print(f"Invalid: {hasher.verify_hash('wrong', expected_hash, HashAlgorithm.SHA256)}")


def demo_binary_analysis():
    """Demonstrate binary analysis capabilities."""
    print("\n" + "=" * 60)
    print("Binary Analysis Demo")
    print("=" * 60)
    
    analyzer = BinaryAnalyzer()
    
    # Hex dump example
    print("\nHex Dump Example:")
    data = b"Hello, World! This is a test of binary data.\x00\x01\x02\xff"
    print(analyzer.hex_dump(data, bytes_per_line=16))
    
    # Binary analysis
    print("\n\nBinary Analysis:")
    analysis = analyzer.analyze_binary(data)
    print(f"Size: {analysis['size']} bytes")
    print(f"Printable ratio: {analysis['printable_ratio']:.2%}")
    print(f"Null bytes: {analysis['null_bytes']}")
    print(f"Entropy: {analysis['entropy']:.2f} bits/byte")
    print(f"High entropy (encrypted/compressed): {analysis['has_high_entropy']}")
    
    # String extraction
    print("\n\nString Extraction:")
    binary_data = b"Some\x00text\x00with\x00\x00embedded\x00strings\x00and\x00\x00binary\xff\xfe\x00data"
    strings = analyzer.find_strings(binary_data, min_length=4)
    print(f"Found {len(strings)} strings:")
    for s in strings:
        print(f"  - {s}")
    
    # Binary comparison
    print("\n\nBinary Comparison:")
    data1 = b"Hello World"
    data2 = b"Hello Earth"
    comparison = analyzer.compare_binary(data1, data2)
    print(f"Data 1: {data1}")
    print(f"Data 2: {data2}")
    print(f"Identical: {comparison['identical']}")
    print(f"Similarity: {comparison['similarity_ratio']:.2%}")
    print(f"Differences at positions: {comparison['diff_positions']}")


def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("OASIS Decoder Utilities Demo")
    print("=" * 60)
    
    demo_basic_encoding()
    demo_encoding_chain()
    demo_auto_decode()
    demo_hashing()
    demo_binary_analysis()
    
    print("\n" + "=" * 60)
    print("Demo Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
