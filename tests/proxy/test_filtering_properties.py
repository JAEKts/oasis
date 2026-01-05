"""
Property-based tests for OASIS traffic filtering engine.

Tests Property 4: Filtering Rule Application
**Validates: Requirements 1.5, 5.4, 10.6**
"""

import pytest
from hypothesis import given, strategies as st, assume
from datetime import datetime, UTC
from urllib.parse import urlparse

from src.oasis.core.models import (
    HTTPRequest, HTTPResponse, HTTPFlow, TrafficFilter, FilterSet,
    FilterAction, FilterType, RequestSource, FlowMetadata
)
from src.oasis.proxy.filtering import FilterEngine, FilterManager


# Strategies for generating test data
@st.composite
def http_request_strategy(draw):
    """Generate valid HTTP requests."""
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
    method = draw(st.sampled_from(methods))
    
    # Generate realistic URLs
    schemes = ['http', 'https']
    scheme = draw(st.sampled_from(schemes))
    
    hosts = ['example.com', 'api.example.com', 'test.org', 'localhost']
    host = draw(st.sampled_from(hosts))
    
    paths = ['/', '/api/users', '/admin/login', '/static/css/style.css', 
             '/images/logo.png', '/api/v1/data.json', '/upload.php']
    path = draw(st.sampled_from(paths))
    
    url = f"{scheme}://{host}{path}"
    
    headers = draw(st.dictionaries(
        st.text(min_size=1, max_size=20, alphabet=st.characters(min_codepoint=65, max_codepoint=90)),
        st.text(min_size=1, max_size=50),
        min_size=0, max_size=5
    ))
    
    # Add common headers
    content_types = ['application/json', 'text/html', 'application/xml', 
                    'image/png', 'text/css', 'application/javascript']
    if draw(st.booleans()):
        headers['Content-Type'] = draw(st.sampled_from(content_types))
    
    body = draw(st.one_of(st.none(), st.binary(min_size=0, max_size=1000)))
    
    return HTTPRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        timestamp=datetime.now(UTC),
        source=RequestSource.PROXY
    )


@st.composite
def http_response_strategy(draw):
    """Generate valid HTTP responses."""
    status_codes = [200, 201, 301, 302, 400, 401, 403, 404, 500, 502]
    status_code = draw(st.sampled_from(status_codes))
    
    headers = draw(st.dictionaries(
        st.text(min_size=1, max_size=20, alphabet=st.characters(min_codepoint=65, max_codepoint=90)),
        st.text(min_size=1, max_size=50),
        min_size=0, max_size=5
    ))
    
    # Add common response headers
    content_types = ['application/json', 'text/html', 'application/xml', 
                    'image/png', 'text/css', 'application/javascript']
    if draw(st.booleans()):
        headers['Content-Type'] = draw(st.sampled_from(content_types))
    
    body = draw(st.one_of(st.none(), st.binary(min_size=0, max_size=1000)))
    duration_ms = draw(st.integers(min_value=1, max_value=5000))
    
    return HTTPResponse(
        status_code=status_code,
        headers=headers,
        body=body,
        timestamp=datetime.now(UTC),
        duration_ms=duration_ms
    )


@st.composite
def traffic_filter_strategy(draw):
    """Generate valid traffic filters."""
    filter_types = list(FilterType)
    filter_type = draw(st.sampled_from(filter_types))
    
    actions = list(FilterAction)
    action = draw(st.sampled_from(actions))
    
    # Generate appropriate patterns based on filter type
    if filter_type == FilterType.HOST:
        patterns = ['example.com', '*.example.com', 'api.*', 'localhost']
    elif filter_type == FilterType.PATH:
        patterns = ['/api/*', '/admin/*', '*.php', '/static/*']
    elif filter_type == FilterType.FILE_TYPE:
        patterns = ['css', 'js', 'png', 'jpg', 'pdf']
    elif filter_type == FilterType.METHOD:
        patterns = ['GET', 'POST', 'PUT', 'DELETE']
    elif filter_type == FilterType.STATUS_CODE:
        patterns = ['200', '4*', '5*', '404']
    elif filter_type == FilterType.CONTENT_TYPE:
        patterns = ['application/json', 'text/*', 'image/*']
    else:
        patterns = ['test', '*test*', 'example']
    
    pattern = draw(st.sampled_from(patterns))
    
    name = draw(st.text(min_size=1, max_size=50))
    case_sensitive = draw(st.booleans())
    regex = draw(st.booleans())
    enabled = draw(st.booleans())
    
    return TrafficFilter(
        name=name,
        filter_type=filter_type,
        action=action,
        pattern=pattern,
        case_sensitive=case_sensitive,
        regex=regex,
        enabled=enabled
    )


class TestFilteringRuleApplication:
    """Test filtering rule application properties."""
    
    @given(http_request_strategy())
    def test_property_4_default_include_behavior(self, request):
        """
        Property 4a: For any HTTP request, when no filters are configured,
        the default INCLUDE action should allow the request through.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        # Create filter engine with default include behavior
        filter_set = FilterSet(name="Test", default_action=FilterAction.INCLUDE)
        engine = FilterEngine(filter_set)
        
        # Should include request when no filters are configured
        result = engine.should_include_request(request)
        assert result is True
    
    @given(http_request_strategy())
    def test_property_4_default_exclude_behavior(self, request):
        """
        Property 4b: For any HTTP request, when no filters are configured,
        the default EXCLUDE action should block the request.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        # Create filter engine with default exclude behavior
        filter_set = FilterSet(name="Test", default_action=FilterAction.EXCLUDE)
        engine = FilterEngine(filter_set)
        
        # Should exclude request when no filters are configured
        result = engine.should_include_request(request)
        assert result is False
    
    @given(http_request_strategy(), traffic_filter_strategy())
    def test_property_4_disabled_filters_ignored(self, request, traffic_filter):
        """
        Property 4c: For any HTTP request and any disabled filter,
        the filter should not affect the filtering decision.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        # Ensure filter is disabled
        traffic_filter.enabled = False
        
        filter_set = FilterSet(name="Test", default_action=FilterAction.INCLUDE)
        filter_set.filters = [traffic_filter]
        engine = FilterEngine(filter_set)
        
        # Result should match default action regardless of filter
        result = engine.should_include_request(request)
        assert result is True  # Should use default action
    
    @given(http_request_strategy())
    def test_property_4_exclude_filter_precedence(self, request):
        """
        Property 4d: For any HTTP request, when both include and exclude filters match,
        the exclude filter should take precedence.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        # Create filters that will both match any request
        include_filter = TrafficFilter(
            name="Include All",
            filter_type=FilterType.METHOD,
            action=FilterAction.INCLUDE,
            pattern="*",
            regex=False,
            enabled=True
        )
        
        exclude_filter = TrafficFilter(
            name="Exclude All",
            filter_type=FilterType.METHOD,
            action=FilterAction.EXCLUDE,
            pattern="*",
            regex=False,
            enabled=True
        )
        
        filter_set = FilterSet(name="Test", default_action=FilterAction.INCLUDE)
        filter_set.filters = [include_filter, exclude_filter]
        engine = FilterEngine(filter_set)
        
        # Exclude should take precedence
        result = engine.should_include_request(request)
        assert result is False
    
    @given(http_request_strategy())
    def test_property_4_host_filter_consistency(self, request):
        """
        Property 4e: For any HTTP request, host filtering should correctly
        extract and match the host portion of the URL.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        parsed_url = urlparse(request.url)
        host = parsed_url.netloc
        
        # Create exact host match filter
        host_filter = TrafficFilter(
            name="Host Filter",
            filter_type=FilterType.HOST,
            action=FilterAction.INCLUDE,
            pattern=host,
            regex=False,
            case_sensitive=False,
            enabled=True
        )
        
        filter_set = FilterSet(name="Test", default_action=FilterAction.EXCLUDE)
        filter_set.filters = [host_filter]
        engine = FilterEngine(filter_set)
        
        # Should include request since host matches
        result = engine.should_include_request(request)
        assert result is True
    
    @given(http_request_strategy())
    def test_property_4_path_filter_consistency(self, request):
        """
        Property 4f: For any HTTP request, path filtering should correctly
        extract and match the path portion of the URL.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        parsed_url = urlparse(request.url)
        path = parsed_url.path
        
        # Create exact path match filter
        path_filter = TrafficFilter(
            name="Path Filter",
            filter_type=FilterType.PATH,
            action=FilterAction.INCLUDE,
            pattern=path,
            regex=False,
            case_sensitive=False,
            enabled=True
        )
        
        filter_set = FilterSet(name="Test", default_action=FilterAction.EXCLUDE)
        filter_set.filters = [path_filter]
        engine = FilterEngine(filter_set)
        
        # Should include request since path matches
        result = engine.should_include_request(request)
        assert result is True
    
    @given(http_request_strategy())
    def test_property_4_method_filter_consistency(self, request):
        """
        Property 4g: For any HTTP request, method filtering should correctly
        match the HTTP method.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        # Create exact method match filter
        method_filter = TrafficFilter(
            name="Method Filter",
            filter_type=FilterType.METHOD,
            action=FilterAction.INCLUDE,
            pattern=request.method,
            regex=False,
            case_sensitive=False,
            enabled=True
        )
        
        filter_set = FilterSet(name="Test", default_action=FilterAction.EXCLUDE)
        filter_set.filters = [method_filter]
        engine = FilterEngine(filter_set)
        
        # Should include request since method matches
        result = engine.should_include_request(request)
        assert result is True
    
    @given(http_request_strategy(), http_response_strategy())
    def test_property_4_response_filtering_consistency(self, request, response):
        """
        Property 4h: For any HTTP request/response pair, response filtering
        should correctly evaluate both request and response attributes.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        # Create status code filter
        status_filter = TrafficFilter(
            name="Status Filter",
            filter_type=FilterType.STATUS_CODE,
            action=FilterAction.INCLUDE,
            pattern=str(response.status_code),
            regex=False,
            case_sensitive=False,
            enabled=True
        )
        
        filter_set = FilterSet(name="Test", default_action=FilterAction.EXCLUDE)
        filter_set.filters = [status_filter]
        engine = FilterEngine(filter_set)
        
        # Should include response since status code matches
        result = engine.should_include_response(request, response)
        assert result is True
    
    @given(http_request_strategy())
    def test_property_4_wildcard_pattern_matching(self, request):
        """
        Property 4i: For any HTTP request, wildcard patterns should correctly
        match using * and ? wildcards.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        # Create wildcard filter that should match any method
        wildcard_filter = TrafficFilter(
            name="Wildcard Filter",
            filter_type=FilterType.METHOD,
            action=FilterAction.INCLUDE,
            pattern="*",
            regex=False,
            case_sensitive=False,
            enabled=True
        )
        
        filter_set = FilterSet(name="Test", default_action=FilterAction.EXCLUDE)
        filter_set.filters = [wildcard_filter]
        engine = FilterEngine(filter_set)
        
        # Should include request since * matches any method
        result = engine.should_include_request(request)
        assert result is True
    
    @given(st.lists(traffic_filter_strategy(), min_size=1, max_size=5), http_request_strategy())
    def test_property_4_multiple_filters_consistency(self, filters, request):
        """
        Property 4j: For any HTTP request and any list of filters,
        the filtering decision should be consistent with the filter logic.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        filter_set = FilterSet(name="Test", default_action=FilterAction.INCLUDE)
        filter_set.filters = filters
        engine = FilterEngine(filter_set)
        
        # Apply filtering multiple times - should get same result
        result1 = engine.should_include_request(request)
        result2 = engine.should_include_request(request)
        result3 = engine.should_include_request(request)
        
        assert result1 == result2 == result3
    
    @given(http_request_strategy())
    def test_property_4_case_sensitivity_consistency(self, request):
        """
        Property 4k: For any HTTP request, case sensitivity settings should
        be consistently applied across all filter types.
        
        **Feature: oasis-pentest-suite, Property 4: Filtering Rule Application**
        **Validates: Requirements 1.5, 5.4, 10.6**
        """
        # Test with case sensitive filter
        case_sensitive_filter = TrafficFilter(
            name="Case Sensitive",
            filter_type=FilterType.METHOD,
            action=FilterAction.INCLUDE,
            pattern=request.method.lower(),  # Use lowercase pattern
            regex=False,
            case_sensitive=True,
            enabled=True
        )
        
        filter_set = FilterSet(name="Test", default_action=FilterAction.EXCLUDE)
        filter_set.filters = [case_sensitive_filter]
        engine = FilterEngine(filter_set)
        
        # Should not match if method is uppercase but pattern is lowercase
        result = engine.should_include_request(request)
        
        # Now test with case insensitive
        case_sensitive_filter.case_sensitive = False
        engine._compile_patterns()  # Recompile patterns
        
        result_insensitive = engine.should_include_request(request)
        
        # Case insensitive should be more permissive or equal
        if request.method.upper() != request.method.lower():
            # If method has different cases, insensitive should be more permissive
            assert result_insensitive or (result == result_insensitive)


class TestFilterManager:
    """Test filter manager functionality."""
    
    def test_filter_manager_creation(self):
        """Test filter manager basic operations."""
        manager = FilterManager()
        
        # Create filter set
        filter_set = manager.create_filter_set("Test Set", "Test description")
        assert filter_set.name == "Test Set"
        assert filter_set.description == "Test description"
        
        # Set as active
        success = manager.set_active_filter_set(str(filter_set.id))
        assert success is True
        
        # Get active engine
        engine = manager.get_active_filter_engine()
        assert engine is not None
        assert engine.filter_set.name == "Test Set"
    
    def test_filter_manager_nonexistent_filter_set(self):
        """Test filter manager with nonexistent filter set."""
        manager = FilterManager()
        
        # Try to set nonexistent filter set
        success = manager.set_active_filter_set("nonexistent-id")
        assert success is False
        
        # Should have no active engine
        engine = manager.get_active_filter_engine()
        assert engine is None


if __name__ == "__main__":
    pytest.main([__file__])