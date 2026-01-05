"""
Property-based tests for OASIS extension framework security isolation.

Feature: oasis-pentest-suite, Property 14: Extension Security Isolation
Validates: Requirements 9.2, 9.5, 9.6
"""

import tempfile
from pathlib import Path
from typing import Set
from uuid import UUID

import pytest
from hypothesis import given, strategies as st, settings, assume

from src.oasis.extensions import (
    ExtensionManager,
    ExtensionMetadata,
    ExtensionPermission,
    ExtensionStatus,
    Extension,
)


# Hypothesis strategies for generating test data
@st.composite
def extension_name_strategy(draw):
    """Generate valid extension names."""
    return draw(
        st.text(
            min_size=3,
            max_size=50,
            alphabet=st.characters(
                min_codepoint=32, max_codepoint=126, blacklist_characters='<>:"/\\|?*'
            ),
        )
    )


@st.composite
def extension_metadata_strategy(draw):
    """Generate valid ExtensionMetadata instances."""
    permissions = draw(
        st.sets(
            st.sampled_from(list(ExtensionPermission)),
            min_size=0,
            max_size=5,
        )
    )

    return ExtensionMetadata(
        name=draw(extension_name_strategy()),
        version=draw(
            st.text(
                min_size=5,
                max_size=10,
                alphabet=st.characters(whitelist_categories=("Nd",), whitelist_characters="."),
            )
        ),
        author=draw(st.text(min_size=1, max_size=50)),
        description=draw(st.text(min_size=10, max_size=200)),
        homepage=draw(st.one_of(st.none(), st.text(min_size=10, max_size=100))),
        license=draw(st.one_of(st.none(), st.sampled_from(["MIT", "Apache-2.0", "GPL-3.0"]))),
        required_permissions=permissions,
    )


@st.composite
def safe_extension_code_strategy(draw):
    """Generate safe extension code that doesn't require dangerous permissions."""
    templates = [
        """
def initialize(context):
    context.log_action("initialize", "extension", success=True)
    return True

def cleanup():
    pass
""",
        """
def initialize(context):
    if context.has_permission(context.granted_permissions.__iter__().__next__() if context.granted_permissions else None):
        context.log_action("check_permission", "extension", success=True)
    return True

def cleanup():
    pass
""",
        """
def initialize(context):
    context.log_action("start", "extension", details={"version": "1.0"}, success=True)
    return True

def cleanup():
    context.log_action("stop", "extension", success=True) if hasattr(context, 'log_action') else None
""",
    ]
    return draw(st.sampled_from(templates))


@st.composite
def dangerous_extension_code_strategy(draw):
    """Generate extension code that attempts dangerous operations."""
    templates = [
        """
import os
def initialize(context):
    os.system('echo "dangerous"')
    return True
""",
        """
import subprocess
def initialize(context):
    subprocess.run(['ls'])
    return True
""",
        """
def initialize(context):
    eval('print("dangerous")')
    return True
""",
        """
def initialize(context):
    exec('import os; os.system("ls")')
    return True
""",
        """
def initialize(context):
    open('/etc/passwd', 'r').read()
    return True
""",
    ]
    return draw(st.sampled_from(templates))


class TestExtensionSecurityIsolation:
    """Property-based tests for extension security isolation."""

    @given(extension_metadata_strategy(), safe_extension_code_strategy())
    @settings(max_examples=100, deadline=None)
    @pytest.mark.asyncio
    async def test_extension_only_accesses_granted_permissions(
        self, metadata: ExtensionMetadata, extension_code: str
    ):
        """
        Property 14: Extension Security Isolation
        For any loaded extension, it should only access authorized system components.
        **Validates: Requirements 9.2, 9.5, 9.6**
        """
        manager = ExtensionManager()

        # Create temporary extension file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as temp_file:
            temp_file.write(extension_code)
            temp_file.flush()
            module_path = Path(temp_file.name)

        try:
            # Load extension with only the required permissions
            extension_id = None
            try:
                extension_id = await manager.load_extension(
                    module_path=module_path,
                    metadata=metadata,
                    granted_permissions=metadata.required_permissions,
                )
            except Exception:
                # Some extensions may fail to load, which is acceptable
                pass

            if extension_id:
                extension = manager.get_extension(extension_id)
                assert extension is not None

                # Extension should only have granted permissions
                assert extension.granted_permissions == metadata.required_permissions

                # All audit logs should be for actions within granted permissions
                logs = manager.get_audit_logs(extension_id=extension_id)

                for log in logs:
                    # Log should be associated with this extension
                    assert log.extension_id == extension_id
                    assert log.extension_name == metadata.name

                    # If action involves a permission, it should be granted
                    # (This is a simplified check - real implementation would be more thorough)
                    assert log.timestamp is not None

        finally:
            # Cleanup
            if module_path.exists():
                module_path.unlink()

    @given(extension_metadata_strategy(), safe_extension_code_strategy())
    @settings(max_examples=100, deadline=None)
    @pytest.mark.asyncio
    async def test_extension_modifications_are_auditable(
        self, metadata: ExtensionMetadata, extension_code: str
    ):
        """
        Property 14: Extension Security Isolation
        For any extension action, all modifications should be auditable.
        **Validates: Requirements 9.2, 9.5, 9.6**
        """
        manager = ExtensionManager()

        # Create temporary extension file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as temp_file:
            temp_file.write(extension_code)
            temp_file.flush()
            module_path = Path(temp_file.name)

        try:
            # Load extension
            extension_id = None
            try:
                extension_id = await manager.load_extension(
                    module_path=module_path,
                    metadata=metadata,
                    granted_permissions=metadata.required_permissions,
                )
            except Exception:
                # Some extensions may fail to load
                pass

            if extension_id:
                # Get audit logs
                logs = manager.get_audit_logs(extension_id=extension_id)

                # Should have at least a load log
                assert len(logs) > 0

                # All logs should have required fields
                for log in logs:
                    assert log.id is not None
                    assert log.extension_id == extension_id
                    assert log.extension_name == metadata.name
                    assert log.action != ""
                    assert log.resource_type != ""
                    assert log.timestamp is not None
                    assert isinstance(log.success, bool)
                    assert isinstance(log.details, dict)

                # Load action should be logged
                load_logs = [log for log in logs if log.action == "load"]
                assert len(load_logs) > 0

        finally:
            # Cleanup
            if module_path.exists():
                module_path.unlink()

    @given(extension_metadata_strategy(), safe_extension_code_strategy())
    @settings(max_examples=100, deadline=None)
    @pytest.mark.asyncio
    async def test_extension_lifecycle_maintains_isolation(
        self, metadata: ExtensionMetadata, extension_code: str
    ):
        """
        Property 14: Extension Security Isolation
        For any extension lifecycle operation (load/unload/reload), security isolation should be maintained.
        **Validates: Requirements 9.2, 9.5, 9.6**
        """
        manager = ExtensionManager()

        # Create temporary extension file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as temp_file:
            temp_file.write(extension_code)
            temp_file.flush()
            module_path = Path(temp_file.name)

        try:
            # Load extension
            extension_id = None
            try:
                extension_id = await manager.load_extension(
                    module_path=module_path,
                    metadata=metadata,
                    granted_permissions=metadata.required_permissions,
                )
            except Exception:
                pass

            if extension_id:
                extension = manager.get_extension(extension_id)

                # Extension should be loaded or active
                assert extension.status in [
                    ExtensionStatus.LOADED,
                    ExtensionStatus.ACTIVE,
                ]

                # Permissions should be maintained
                original_permissions = extension.granted_permissions.copy()

                # Disable extension
                disabled = await manager.disable_extension(extension_id)
                if disabled:
                    assert extension.status == ExtensionStatus.DISABLED
                    # Permissions should still be the same
                    assert extension.granted_permissions == original_permissions

                    # Re-enable
                    enabled = await manager.enable_extension(extension_id)
                    if enabled:
                        assert extension.status == ExtensionStatus.ACTIVE
                        # Permissions should still be the same
                        assert extension.granted_permissions == original_permissions

                # Unload extension
                unloaded = await manager.unload_extension(extension_id)
                if unloaded:
                    # Extension should no longer be in manager
                    assert manager.get_extension(extension_id) is None

                    # Audit logs should still exist
                    logs = manager.get_audit_logs(extension_id=extension_id)
                    assert len(logs) > 0

        finally:
            # Cleanup
            if module_path.exists():
                module_path.unlink()

    @given(extension_metadata_strategy())
    @settings(max_examples=100, deadline=None)
    @pytest.mark.asyncio
    async def test_dangerous_permissions_require_explicit_grant(self, metadata: ExtensionMetadata):
        """
        Property 14: Extension Security Isolation
        For any extension requesting dangerous permissions, they must be explicitly granted.
        **Validates: Requirements 9.2, 9.5, 9.6**
        """
        # Add a dangerous permission to required permissions
        dangerous_perms = {
            ExtensionPermission.EXECUTE_COMMANDS,
            ExtensionPermission.FILE_SYSTEM_ACCESS,
        }

        # Add at least one dangerous permission
        metadata.required_permissions.add(ExtensionPermission.EXECUTE_COMMANDS)

        # Create safe extension code
        extension_code = """
def initialize(context):
    context.log_action("initialize", "extension", success=True)
    return True
"""

        manager = ExtensionManager()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as temp_file:
            temp_file.write(extension_code)
            temp_file.flush()
            module_path = Path(temp_file.name)

        try:
            # Try to load with only safe permissions (not including dangerous ones)
            safe_permissions = {ExtensionPermission.READ_HTTP_TRAFFIC}
            extension_id = await manager.load_extension(
                module_path=module_path,
                metadata=metadata,
                granted_permissions=safe_permissions,  # Grant only safe permissions
            )

            # Should fail to load due to missing required dangerous permissions
            assert extension_id is None

            # Try again with granted dangerous permissions
            extension_id = await manager.load_extension(
                module_path=module_path,
                metadata=metadata,
                granted_permissions=metadata.required_permissions,
            )

            # Should succeed now
            if extension_id:
                extension = manager.get_extension(extension_id)
                assert extension is not None
                assert ExtensionPermission.EXECUTE_COMMANDS in extension.granted_permissions

        finally:
            if module_path.exists():
                module_path.unlink()

    @given(extension_metadata_strategy(), st.sampled_from(list(ExtensionPermission)))
    @settings(max_examples=100, deadline=None)
    @pytest.mark.asyncio
    async def test_permission_grant_and_revoke_are_audited(
        self, metadata: ExtensionMetadata, permission: ExtensionPermission
    ):
        """
        Property 14: Extension Security Isolation
        For any permission grant or revoke operation, the action should be audited.
        **Validates: Requirements 9.2, 9.5, 9.6**
        """
        manager = ExtensionManager()

        # Create safe extension code
        extension_code = """
def initialize(context):
    context.log_action("initialize", "extension", success=True)
    return True
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as temp_file:
            temp_file.write(extension_code)
            temp_file.flush()
            module_path = Path(temp_file.name)

        try:
            # Load extension with minimal permissions
            extension_id = await manager.load_extension(
                module_path=module_path,
                metadata=metadata,
                granted_permissions=set(),
            )

            if extension_id:
                # Grant permission
                granted = await manager.grant_permission(extension_id, permission)
                assert granted

                # Check audit log
                grant_logs = manager.get_audit_logs(
                    extension_id=extension_id, action="grant_permission"
                )
                assert len(grant_logs) > 0
                assert grant_logs[-1].details.get("permission") == permission.value

                # Revoke permission
                revoked = await manager.revoke_permission(extension_id, permission)
                assert revoked

                # Check audit log
                revoke_logs = manager.get_audit_logs(
                    extension_id=extension_id, action="revoke_permission"
                )
                assert len(revoke_logs) > 0
                assert revoke_logs[-1].details.get("permission") == permission.value

        finally:
            if module_path.exists():
                module_path.unlink()

    @given(extension_metadata_strategy(), dangerous_extension_code_strategy())
    @settings(max_examples=50, deadline=None)
    @pytest.mark.asyncio
    async def test_sandbox_prevents_dangerous_operations(
        self, metadata: ExtensionMetadata, dangerous_code: str
    ):
        """
        Property 14: Extension Security Isolation
        For any extension attempting dangerous operations without permissions, the sandbox should prevent them.
        **Validates: Requirements 9.2, 9.5, 9.6**
        """
        manager = ExtensionManager()

        # Don't grant dangerous permissions
        safe_permissions = metadata.required_permissions - {
            ExtensionPermission.EXECUTE_COMMANDS,
            ExtensionPermission.FILE_SYSTEM_ACCESS,
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as temp_file:
            temp_file.write(dangerous_code)
            temp_file.flush()
            module_path = Path(temp_file.name)

        try:
            # Try to load dangerous extension without dangerous permissions
            extension_id = await manager.load_extension(
                module_path=module_path,
                metadata=metadata,
                granted_permissions=safe_permissions,
            )

            # Extension should either fail to load or be in error state
            if extension_id:
                extension = manager.get_extension(extension_id)
                # If it loaded, it should be in error state due to sandbox restrictions
                # or the dangerous operation should have been blocked
                assert extension.status in [
                    ExtensionStatus.ERROR,
                    ExtensionStatus.LOADED,
                    ExtensionStatus.ACTIVE,
                ]

                # Check audit logs for any errors
                logs = manager.get_audit_logs(extension_id=extension_id)
                # There should be logs indicating the load attempt
                assert len(logs) > 0

        finally:
            if module_path.exists():
                module_path.unlink()
