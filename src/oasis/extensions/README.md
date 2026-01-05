# OASIS Extension Framework

The Extension Framework provides a secure, sandboxed environment for extending OASIS functionality with custom plugins and integrations.

## Features

- **Plugin API**: Clean API for extensions to interact with OASIS components
- **Security Sandboxing**: Restricted execution environment to prevent malicious code
- **Permission System**: Granular permissions for controlling extension access
- **Audit Logging**: Complete audit trail of all extension actions
- **Lifecycle Management**: Load, unload, enable, disable, and update extensions

## Architecture

### Components

1. **ExtensionManager**: Manages extension lifecycle and permissions
2. **ExtensionSandbox**: Provides security isolation for extension code
3. **ExtensionAPI**: Public API that extensions use to interact with OASIS
4. **ExtensionContext**: Runtime context with extension identity and permissions
5. **AuditLogger**: Tracks all extension actions for security auditing

### Permission Model

Extensions must declare required permissions in their metadata. Available permissions:

- `READ_HTTP_TRAFFIC`: Read intercepted HTTP traffic
- `MODIFY_HTTP_TRAFFIC`: Modify HTTP requests/responses
- `READ_SCAN_RESULTS`: Access vulnerability scan results
- `MODIFY_SCAN_RESULTS`: Add or modify scan findings
- `TRIGGER_SCANS`: Initiate vulnerability scans
- `ADD_UI_COMPONENTS`: Register UI components
- `MODIFY_UI_COMPONENTS`: Modify existing UI
- `READ_PROJECT_DATA`: Read project data
- `WRITE_PROJECT_DATA`: Write project data
- `EXECUTE_COMMANDS`: Execute system commands (dangerous)
- `NETWORK_ACCESS`: Make network requests
- `FILE_SYSTEM_ACCESS`: Access file system (dangerous)

## Creating an Extension

### Basic Extension Structure

```python
# my_extension.py

from oasis.extensions import ExtensionContext, ExtensionAPI

def initialize(context: ExtensionContext):
    """
    Entry point called when extension is loaded.
    
    Args:
        context: Extension context with identity and permissions
    """
    print(f"Extension {context.extension_name} loaded!")
    
    # Log the initialization
    context.log_action(
        action="initialize",
        resource_type="extension",
        success=True
    )

def cleanup():
    """
    Optional cleanup function called when extension is unloaded.
    """
    print("Extension unloaded!")
```

### Extension Metadata

```python
from oasis.extensions import ExtensionMetadata, ExtensionPermission

metadata = ExtensionMetadata(
    name="My Custom Extension",
    version="1.0.0",
    author="Your Name",
    description="Does something useful",
    homepage="https://github.com/yourname/extension",
    license="MIT",
    required_permissions={
        ExtensionPermission.READ_HTTP_TRAFFIC,
        ExtensionPermission.READ_SCAN_RESULTS,
    },
    python_version=">=3.11",
    oasis_version=">=1.0.0",
)
```

### Loading an Extension

```python
from pathlib import Path
from oasis.extensions import ExtensionManager

manager = ExtensionManager()

# Load extension
extension_id = await manager.load_extension(
    module_path=Path("my_extension.py"),
    metadata=metadata,
)

if extension_id:
    print(f"Extension loaded with ID: {extension_id}")
else:
    print("Failed to load extension")
```

## Security Considerations

### Sandboxing

Extensions run in a restricted environment:

- Limited built-in functions (no `eval`, `exec`, `open`, etc.)
- No direct access to `os`, `subprocess`, or `sys` modules
- All OASIS access goes through the controlled API
- Actions are logged for audit trails

### Permission Checks

All API methods check permissions before execution:

```python
class MyExtensionAPI(ExtensionAPI):
    async def get_http_flows(self, project_id=None, limit=100):
        # Check permission
        self.check_permission(ExtensionPermission.READ_HTTP_TRAFFIC)
        
        # Log the action
        self.context.log_action(
            action="get_http_flows",
            resource_type="http_flow",
            details={"limit": limit}
        )
        
        # Perform the operation
        return await self._fetch_flows(project_id, limit)
```

### Audit Trail

All extension actions are logged:

```python
# Get audit logs for an extension
logs = manager.get_audit_logs(extension_id=extension_id)

for log in logs:
    print(f"{log.timestamp}: {log.action} on {log.resource_type}")
    if not log.success:
        print(f"  Error: {log.error_message}")
```

## Example: HTTP Traffic Logger Extension

```python
from oasis.extensions import ExtensionContext, ExtensionAPI

class TrafficLoggerAPI(ExtensionAPI):
    async def log_traffic(self):
        """Log all HTTP traffic to a file"""
        self.check_permission(ExtensionPermission.READ_HTTP_TRAFFIC)
        
        flows = await self.get_http_flows(limit=1000)
        
        with open("traffic_log.txt", "w") as f:
            for request, response in flows:
                f.write(f"{request.method} {request.url}\n")
                if response:
                    f.write(f"  Status: {response.status_code}\n")

def initialize(context: ExtensionContext):
    api = TrafficLoggerAPI(context)
    
    # Start logging in background
    import asyncio
    asyncio.create_task(api.log_traffic())
    
    context.log_action(
        action="start_logging",
        resource_type="traffic",
        success=True
    )
```

## Testing Extensions

Extensions should be thoroughly tested before deployment:

1. **Unit Tests**: Test extension logic in isolation
2. **Integration Tests**: Test interaction with OASIS API
3. **Security Tests**: Verify sandbox restrictions work
4. **Permission Tests**: Ensure permission checks are enforced

## Best Practices

1. **Minimal Permissions**: Request only the permissions you need
2. **Error Handling**: Handle errors gracefully and log failures
3. **Resource Cleanup**: Implement `cleanup()` function for proper shutdown
4. **Audit Logging**: Log significant actions for transparency
5. **Documentation**: Provide clear documentation for users
6. **Version Compatibility**: Specify compatible OASIS versions
