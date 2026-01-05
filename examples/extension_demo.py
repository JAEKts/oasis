"""
OASIS Extension Framework Demo

Demonstrates how to create and use extensions with the OASIS extension framework.
"""

import asyncio
from pathlib import Path
import tempfile
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.oasis.extensions import (
    ExtensionManager,
    ExtensionMetadata,
    ExtensionPermission,
    OASISExtensionAPI,
    RollbackManager,
)


# Example 1: Simple Extension
SIMPLE_EXTENSION = """
def initialize(context):
    '''Simple extension that logs its initialization.'''
    print(f"Extension '{context.extension_name}' initialized!")
    
    context.log_action(
        action="initialize",
        resource_type="extension",
        details={"message": "Extension started successfully"},
        success=True
    )
    
    return True

def cleanup():
    '''Cleanup function called when extension is unloaded.'''
    print("Extension cleanup complete!")
"""


# Example 2: HTTP Traffic Logger Extension
HTTP_LOGGER_EXTENSION = """
async def initialize(context):
    '''Extension that logs HTTP traffic.'''
    print(f"HTTP Logger Extension '{context.extension_name}' initialized!")
    
    # Check if we have the required permission
    if context.has_permission(context.granted_permissions.__iter__().__next__() if context.granted_permissions else None):
        context.log_action(
            action="initialize",
            resource_type="extension",
            details={"message": "HTTP logger ready"},
            success=True
        )
    
    return True

def cleanup():
    print("HTTP Logger Extension cleanup complete!")
"""


# Example 3: Scanner Integration Extension
SCANNER_EXTENSION = """
def initialize(context):
    '''Extension that integrates with the vulnerability scanner.'''
    print(f"Scanner Extension '{context.extension_name}' initialized!")
    
    context.log_action(
        action="initialize",
        resource_type="extension",
        details={"message": "Scanner integration ready"},
        success=True
    )
    
    return True

def cleanup():
    print("Scanner Extension cleanup complete!")
"""


async def demo_simple_extension():
    """Demonstrate loading a simple extension."""
    print("\n=== Demo 1: Simple Extension ===\n")

    manager = ExtensionManager()

    # Create extension metadata
    metadata = ExtensionMetadata(
        name="Simple Demo Extension",
        version="1.0.0",
        author="OASIS Team",
        description="A simple demonstration extension",
        license="MIT",
        required_permissions=set(),  # No special permissions needed
    )

    # Create temporary extension file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False
    ) as temp_file:
        temp_file.write(SIMPLE_EXTENSION)
        temp_file.flush()
        module_path = Path(temp_file.name)

    try:
        # Load the extension
        extension_id = await manager.load_extension(
            module_path=module_path,
            metadata=metadata,
        )

        if extension_id:
            print(f"✓ Extension loaded successfully with ID: {extension_id}")

            # Get extension info
            extension = manager.get_extension(extension_id)
            print(f"  Status: {extension.status.value}")
            print(f"  Loaded at: {extension.loaded_at}")

            # Get audit logs
            logs = manager.get_audit_logs(extension_id=extension_id)
            print(f"\n  Audit logs ({len(logs)} entries):")
            for log in logs:
                print(f"    - {log.action}: {log.success}")

            # Unload the extension
            await manager.unload_extension(extension_id)
            print("\n✓ Extension unloaded successfully")

        else:
            print("✗ Failed to load extension")

    finally:
        if module_path.exists():
            module_path.unlink()


async def demo_permission_system():
    """Demonstrate the permission system."""
    print("\n=== Demo 2: Permission System ===\n")

    manager = ExtensionManager()

    # Create extension with specific permissions
    metadata = ExtensionMetadata(
        name="HTTP Logger Extension",
        version="1.0.0",
        author="OASIS Team",
        description="Logs HTTP traffic",
        required_permissions={
            ExtensionPermission.READ_HTTP_TRAFFIC,
        },
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False
    ) as temp_file:
        temp_file.write(HTTP_LOGGER_EXTENSION)
        temp_file.flush()
        module_path = Path(temp_file.name)

    try:
        # Load with granted permissions
        extension_id = await manager.load_extension(
            module_path=module_path,
            metadata=metadata,
            granted_permissions={ExtensionPermission.READ_HTTP_TRAFFIC},
        )

        if extension_id:
            print(f"✓ Extension loaded with permissions")

            extension = manager.get_extension(extension_id)
            print(f"  Granted permissions:")
            for perm in extension.granted_permissions:
                print(f"    - {perm.value}")

            # Grant additional permission
            await manager.grant_permission(
                extension_id, ExtensionPermission.READ_SCAN_RESULTS
            )
            print(f"\n✓ Granted additional permission: READ_SCAN_RESULTS")

            print(f"  Updated permissions:")
            for perm in extension.granted_permissions:
                print(f"    - {perm.value}")

            # Revoke permission
            await manager.revoke_permission(
                extension_id, ExtensionPermission.READ_SCAN_RESULTS
            )
            print(f"\n✓ Revoked permission: READ_SCAN_RESULTS")

            # Check audit logs for permission changes
            perm_logs = manager.get_audit_logs(
                extension_id=extension_id, action="grant_permission"
            )
            print(f"\n  Permission grant logs: {len(perm_logs)}")

            await manager.unload_extension(extension_id)

    finally:
        if module_path.exists():
            module_path.unlink()


async def demo_lifecycle_management():
    """Demonstrate extension lifecycle management."""
    print("\n=== Demo 3: Lifecycle Management ===\n")

    manager = ExtensionManager()

    metadata = ExtensionMetadata(
        name="Lifecycle Demo Extension",
        version="1.0.0",
        author="OASIS Team",
        description="Demonstrates lifecycle management",
        required_permissions=set(),
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False
    ) as temp_file:
        temp_file.write(SIMPLE_EXTENSION)
        temp_file.flush()
        module_path = Path(temp_file.name)

    try:
        # Load extension
        extension_id = await manager.load_extension(
            module_path=module_path, metadata=metadata
        )

        if extension_id:
            extension = manager.get_extension(extension_id)
            print(f"✓ Extension loaded - Status: {extension.status.value}")

            # Disable extension
            await manager.disable_extension(extension_id)
            print(f"✓ Extension disabled - Status: {extension.status.value}")

            # Re-enable extension
            await manager.enable_extension(extension_id)
            print(f"✓ Extension enabled - Status: {extension.status.value}")

            # Get all extensions
            all_extensions = manager.get_all_extensions()
            print(f"\n  Total extensions loaded: {len(all_extensions)}")

            # Get active extensions
            active_extensions = manager.get_extensions_by_status(
                extension.status
            )
            print(f"  Active extensions: {len(active_extensions)}")

            await manager.unload_extension(extension_id)
            print(f"\n✓ Extension unloaded")

    finally:
        if module_path.exists():
            module_path.unlink()


async def demo_rollback_manager():
    """Demonstrate rollback capabilities."""
    print("\n=== Demo 4: Rollback Manager ===\n")

    rollback_mgr = RollbackManager()

    # Create some test data
    original_data = {
        "url": "https://example.com/api",
        "method": "GET",
        "headers": {"User-Agent": "OASIS/1.0"},
    }

    # Create snapshot before modification
    snapshot_id = rollback_mgr.create_snapshot(
        resource_type="http_flow",
        resource_id="flow-123",
        data=original_data,
    )
    print(f"✓ Created snapshot: {snapshot_id}")

    # Simulate modification
    modified_data = original_data.copy()
    modified_data["method"] = "POST"
    modified_data["headers"]["Content-Type"] = "application/json"

    print(f"\n  Original method: {original_data['method']}")
    print(f"  Modified method: {modified_data['method']}")

    # Rollback to snapshot
    restored_data = rollback_mgr.rollback(snapshot_id)
    print(f"\n✓ Rolled back to snapshot")
    print(f"  Restored method: {restored_data['method']}")

    # Get all snapshots
    snapshots = rollback_mgr.get_snapshots(resource_type="http_flow")
    print(f"\n  Total snapshots for http_flow: {len(snapshots)}")

    # Clear snapshots
    cleared = rollback_mgr.clear_snapshots(resource_type="http_flow")
    print(f"✓ Cleared {cleared} snapshots")


async def main():
    """Run all demos."""
    print("=" * 60)
    print("OASIS Extension Framework Demo")
    print("=" * 60)

    await demo_simple_extension()
    await demo_permission_system()
    await demo_lifecycle_management()
    await demo_rollback_manager()

    print("\n" + "=" * 60)
    print("All demos completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
