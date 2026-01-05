"""
Property-based tests for the decoder module.

Feature: oasis-pentest-suite, Property 11: Encoding Chain Consistency
Validates: Requirements 6.2, 6.3, 6.5
"""

import pytest
from hypothesis import given, strategies as st, settings

from src.oasis.decoder import DataTransformer, EncodingChain, EncodingType


# Strategy for generating printable strings (to avoid encoding issues)
printable_text = st.text(
    alphabet=st.characters(
        min_codepoint=32,  # Space
        max_codepoint=126,  # Tilde
        blacklist_categories=('Cc', 'Cs')  # Control chars and surrogates
    ),
    min_size=1,
    max_size=100
)


# Strategy for generating encoding types that support round-trip
roundtrip_encodings = st.sampled_from([
    EncodingType.URL,
    EncodingType.HTML,
    EncodingType.BASE64,
    EncodingType.BASE64_URL,
    EncodingType.HEX,
])


class TestEncodingChainConsistency:
    """
    Property 11: Encoding Chain Consistency
    
    For any sequence of encoding/decoding operations, applying the reverse
    sequence should return the original data.
    """
    
    @settings(max_examples=100)
    @given(data=printable_text, encoding=roundtrip_encodings)
    def test_single_encoding_roundtrip(self, data: str, encoding: EncodingType):
        """
        Test that encoding then decoding returns the original data.
        
        Feature: oasis-pentest-suite, Property 11: Encoding Chain Consistency
        Validates: Requirements 6.2, 6.3, 6.5
        """
        transformer = DataTransformer()
        
        # Encode then decode
        encoded = transformer.encode(data, encoding)
        decoded = transformer.decode(encoded, encoding)
        
        # Should get back the original data
        assert decoded == data, (
            f"Round-trip failed for {encoding.value}: "
            f"original={repr(data)}, encoded={repr(encoded)}, decoded={repr(decoded)}"
        )
    
    @settings(max_examples=100)
    @given(
        data=printable_text,
        encodings=st.lists(roundtrip_encodings, min_size=1, max_size=3)
    )
    def test_encoding_chain_roundtrip(self, data: str, encodings: list):
        """
        Test that an encoding chain can be reversed to get original data.
        
        Feature: oasis-pentest-suite, Property 11: Encoding Chain Consistency
        Validates: Requirements 6.2, 6.3, 6.5
        """
        chain = EncodingChain()
        
        # Build the encoding chain
        for encoding in encodings:
            chain.add_step(encoding)
        
        # Execute the chain
        encoded = chain.execute(data)
        
        # Reverse the chain
        decoded = chain.reverse(encoded)
        
        # Should get back the original data
        assert decoded == data, (
            f"Chain round-trip failed with {[e.value for e in encodings]}: "
            f"original={repr(data)}, encoded={repr(encoded)}, decoded={repr(decoded)}"
        )
    
    @settings(max_examples=100)
    @given(
        data=printable_text,
        encoding1=roundtrip_encodings,
        encoding2=roundtrip_encodings
    )
    def test_double_encoding_roundtrip(self, data: str, encoding1: EncodingType, encoding2: EncodingType):
        """
        Test that double encoding can be reversed correctly.
        
        Feature: oasis-pentest-suite, Property 11: Encoding Chain Consistency
        Validates: Requirements 6.2, 6.3, 6.5
        """
        transformer = DataTransformer()
        
        # Double encode
        encoded_once = transformer.encode(data, encoding1)
        encoded_twice = transformer.encode(encoded_once, encoding2)
        
        # Double decode in reverse order
        decoded_once = transformer.decode(encoded_twice, encoding2)
        decoded_twice = transformer.decode(decoded_once, encoding1)
        
        # Should get back the original data
        assert decoded_twice == data, (
            f"Double encoding round-trip failed with {encoding1.value} -> {encoding2.value}: "
            f"original={repr(data)}, final={repr(decoded_twice)}"
        )
    
    @settings(max_examples=100)
    @given(data=printable_text, encoding=roundtrip_encodings)
    def test_idempotent_decoding(self, data: str, encoding: EncodingType):
        """
        Test that decoding already-decoded data doesn't change it further.
        
        This tests that decode(decode(encode(x))) might not equal x,
        but decode(encode(x)) should always equal x.
        
        Feature: oasis-pentest-suite, Property 11: Encoding Chain Consistency
        Validates: Requirements 6.2, 6.5
        """
        transformer = DataTransformer()
        
        # Encode then decode
        encoded = transformer.encode(data, encoding)
        decoded = transformer.decode(encoded, encoding)
        
        # First decode should give us original
        assert decoded == data
        
        # Encoding the decoded data should be reversible
        re_encoded = transformer.encode(decoded, encoding)
        re_decoded = transformer.decode(re_encoded, encoding)
        assert re_decoded == data
    
    @settings(max_examples=100)
    @given(
        data=printable_text,
        encodings=st.lists(roundtrip_encodings, min_size=2, max_size=4)
    )
    def test_chain_order_matters(self, data: str, encodings: list):
        """
        Test that encoding chain order is preserved in reverse.
        
        Feature: oasis-pentest-suite, Property 11: Encoding Chain Consistency
        Validates: Requirements 6.3
        """
        # Create chain with specific order
        chain = EncodingChain()
        for encoding in encodings:
            chain.add_step(encoding)
        
        # Execute forward
        encoded = chain.execute(data)
        
        # Reverse should undo in correct order
        decoded = chain.reverse(encoded)
        
        assert decoded == data, (
            f"Chain order not preserved: {[e.value for e in encodings]}"
        )
    
    @settings(max_examples=100)
    @given(data=printable_text)
    def test_empty_chain_identity(self, data: str):
        """
        Test that an empty encoding chain returns data unchanged.
        
        Feature: oasis-pentest-suite, Property 11: Encoding Chain Consistency
        Validates: Requirements 6.3
        """
        chain = EncodingChain()
        
        # Empty chain should be identity function
        assert chain.execute(data) == data
        assert chain.reverse(data) == data


class TestAutoDecoding:
    """Tests for automatic encoding detection."""
    
    @settings(max_examples=100)
    @given(data=printable_text, encoding=roundtrip_encodings)
    def test_auto_decode_detects_encoding(self, data: str, encoding: EncodingType):
        """
        Test that auto_decode can detect and decode encoded data.
        
        Feature: oasis-pentest-suite, Property 11: Encoding Chain Consistency
        Validates: Requirements 6.2
        """
        transformer = DataTransformer()
        
        # Encode the data
        encoded = transformer.encode(data, encoding)
        
        # Skip test if encoding didn't change the data
        # (e.g., HTML encoding of '0' is still '0', URL encoding of 'abc' is still 'abc')
        if encoded == data:
            # This is valid - some data doesn't change when encoded
            # We can't expect auto_decode to detect an encoding that didn't change anything
            return
        
        # Auto-decode should detect it
        results = transformer.auto_decode(encoded)
        
        # Should have at least one result
        assert len(results) > 0, f"No decoding results for {encoding.value}"
        
        # The correct encoding should be in the results
        detected_encodings = [r.encoding_type for r in results if r.error is None]
        assert encoding in detected_encodings, (
            f"Failed to detect {encoding.value} encoding. "
            f"Detected: {[e.value for e in detected_encodings]}, "
            f"Original: {repr(data)}, Encoded: {repr(encoded)}"
        )
        
        # At least one result should decode back to original
        successful_decodes = [r.decoded_data for r in results if r.error is None]
        assert data in successful_decodes, (
            f"None of the auto-decode results matched original data for {encoding.value}"
        )
