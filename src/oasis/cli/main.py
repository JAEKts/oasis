"""
OASIS CLI Main Entry Point

Command-line interface for OASIS automation and scripting.
"""

import sys
import json
from pathlib import Path
from typing import Optional
import click

from ..core.models import Project, ProjectSettings, HTTPRequest
from ..storage.vault import VaultStorage
from ..scanner.engine import ScanEngine
from ..scanner.policy import ScanPolicy, ScanIntensity


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """
    OASIS - Open Architecture Security Interception Suite

    Command-line interface for penetration testing automation.
    """
    pass


@cli.group()
def project():
    """Project management commands."""
    pass


@project.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="Project description")
@click.option("--scope", "-s", multiple=True, help="Target scope patterns")
@click.option("--vault-path", default="./data/vault", help="Vault storage path")
def create_project(name: str, description: str, scope: tuple, vault_path: str):
    """
    Create a new project.

    Example:
        oasis project create "Web App Test" -s "https://example.com/*"
    """
    vault = VaultStorage(Path(vault_path))

    project = Project(
        name=name,
        description=description,
        settings=ProjectSettings(target_scope=list(scope)),
    )

    project_id = vault.create_project(project)

    click.echo(f"✓ Created project: {name}")
    click.echo(f"  ID: {project_id}")
    click.echo(f"  Scope: {', '.join(scope) if scope else 'None'}")


@project.command("list")
@click.option("--vault-path", default="./data/vault", help="Vault storage path")
def list_projects(vault_path: str):
    """
    List all projects.

    Example:
        oasis project list
    """
    vault = VaultStorage(Path(vault_path))
    projects = vault.list_projects()

    if not projects:
        click.echo("No projects found.")
        return

    click.echo(f"\nFound {len(projects)} project(s):\n")

    for p in projects:
        click.echo(f"  • {p.name}")
        click.echo(f"    ID: {p.id}")
        click.echo(f"    Created: {p.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        click.echo(
            f"    Scope: {', '.join(p.settings.target_scope) if p.settings.target_scope else 'None'}"
        )
        click.echo()


@project.command("info")
@click.argument("project_id")
@click.option("--vault-path", default="./data/vault", help="Vault storage path")
def project_info(project_id: str, vault_path: str):
    """
    Show project information.

    Example:
        oasis project info <project-id>
    """
    from uuid import UUID

    vault = VaultStorage(Path(vault_path))
    project = vault.get_project(UUID(project_id))

    if not project:
        click.echo(f"✗ Project not found: {project_id}", err=True)
        sys.exit(1)

    click.echo(f"\nProject: {project.name}")
    click.echo(f"ID: {project.id}")
    click.echo(f"Description: {project.description}")
    click.echo(f"Created: {project.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
    click.echo(f"\nScope:")
    for scope in project.settings.target_scope:
        click.echo(f"  • {scope}")

    # Show statistics
    flows = vault.get_flows(project.id)
    findings = vault.get_findings(project.id)

    click.echo(f"\nStatistics:")
    click.echo(f"  Flows: {len(flows)}")
    click.echo(f"  Findings: {len(findings)}")


@cli.group()
def scan():
    """Vulnerability scanning commands."""
    pass


@scan.command("start")
@click.argument("project_id")
@click.option("--checks", "-c", multiple=True, help="Vulnerability checks to run")
@click.option(
    "--intensity",
    "-i",
    type=click.Choice(["light", "normal", "thorough"]),
    default="normal",
)
@click.option("--vault-path", default="./data/vault", help="Vault storage path")
def start_scan(project_id: str, checks: tuple, intensity: str, vault_path: str):
    """
    Start a vulnerability scan.

    Example:
        oasis scan start <project-id> -c sql_injection -c xss
    """
    from uuid import UUID

    vault = VaultStorage(Path(vault_path))
    project = vault.get_project(UUID(project_id))

    if not project:
        click.echo(f"✗ Project not found: {project_id}", err=True)
        sys.exit(1)

    # Get flows to scan
    flows = vault.get_flows(project.id)

    if not flows:
        click.echo("✗ No flows found to scan", err=True)
        sys.exit(1)

    click.echo(f"Starting scan on {len(flows)} flow(s)...")

    # Configure scan
    enabled_checks = list(checks) if checks else ["sql_injection", "xss", "csrf"]
    intensity_map = {
        "light": ScanIntensity.LIGHT,
        "normal": ScanIntensity.NORMAL,
        "thorough": ScanIntensity.THOROUGH,
    }

    policy = ScanPolicy(
        enabled_checks=enabled_checks, scan_intensity=intensity_map[intensity]
    )

    # Run scan
    scan_engine = ScanEngine()
    findings = scan_engine.passive_scan(flows, policy)

    # Store findings
    for finding in findings:
        vault.store_finding(project.id, finding)

    click.echo(f"✓ Scan complete")
    click.echo(f"  Found {len(findings)} issue(s)")

    # Show summary by severity
    from collections import Counter

    severity_counts = Counter(f.severity.value for f in findings)

    if severity_counts:
        click.echo(f"\nFindings by severity:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                click.echo(f"  {severity.capitalize()}: {count}")


@cli.group()
def export():
    """Data export commands."""
    pass


@export.command("findings")
@click.argument("project_id")
@click.option(
    "--format", "-f", type=click.Choice(["json", "csv", "xml"]), default="json"
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--vault-path", default="./data/vault", help="Vault storage path")
def export_findings(
    project_id: str, format: str, output: Optional[str], vault_path: str
):
    """
    Export vulnerability findings.

    Example:
        oasis export findings <project-id> -f json -o findings.json
    """
    from uuid import UUID

    vault = VaultStorage(Path(vault_path))
    project = vault.get_project(UUID(project_id))

    if not project:
        click.echo(f"✗ Project not found: {project_id}", err=True)
        sys.exit(1)

    findings = vault.get_findings(project.id)

    if not findings:
        click.echo("No findings to export", err=True)
        sys.exit(1)

    # Export based on format
    if format == "json":
        data = {
            "project": {
                "id": str(project.id),
                "name": project.name,
                "description": project.description,
            },
            "findings": [f.model_dump() for f in findings],
        }

        output_str = json.dumps(data, indent=2, default=str)

    elif format == "csv":
        import csv
        import io

        output_io = io.StringIO()
        writer = csv.writer(output_io)

        # Write header
        writer.writerow(["ID", "Type", "Severity", "Title", "Description"])

        # Write findings
        for f in findings:
            writer.writerow(
                [
                    str(f.id),
                    f.vulnerability_type.value,
                    f.severity.value,
                    f.title,
                    f.description,
                ]
            )

        output_str = output_io.getvalue()

    else:  # xml
        output_str = "<?xml version='1.0' encoding='UTF-8'?>\n<findings>\n"
        for f in findings:
            output_str += f"  <finding id='{f.id}'>\n"
            output_str += f"    <type>{f.vulnerability_type.value}</type>\n"
            output_str += f"    <severity>{f.severity.value}</severity>\n"
            output_str += f"    <title>{f.title}</title>\n"
            output_str += f"  </finding>\n"
        output_str += "</findings>\n"

    # Write to file or stdout
    if output:
        Path(output).write_text(output_str)
        click.echo(f"✓ Exported {len(findings)} finding(s) to {output}")
    else:
        click.echo(output_str)


@cli.command()
@click.option("--host", default="127.0.0.1", help="API server host")
@click.option("--port", default=8000, help="API server port")
def serve(host: str, port: int):
    """
    Start the OASIS API server.

    Example:
        oasis serve --host 0.0.0.0 --port 8080
    """
    import uvicorn
    from ..api.app import app

    click.echo(f"Starting OASIS API server on {host}:{port}")
    click.echo(f"API documentation: http://{host}:{port}/api/docs")

    uvicorn.run(app, host=host, port=port)


def main():
    """Main entry point for CLI."""
    cli()


if __name__ == "__main__":
    main()
