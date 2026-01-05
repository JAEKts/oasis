# OASIS API Documentation

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
  - [Starting the API Server](#starting-the-api-server)
  - [API Documentation](#api-documentation)
- [Authentication](#authentication)
- [Common Use Cases](#common-use-cases)
  - [1. Create a Project](#1-create-a-project)
  - [2. List HTTP Flows](#2-list-http-flows)
  - [3. Start a Vulnerability Scan](#3-start-a-vulnerability-scan)
  - [4. Export Findings](#4-export-findings)
- [CLI Usage](#cli-usage)
  - [Project Management](#project-management)
  - [Vulnerability Scanning](#vulnerability-scanning)
- [External Tool Integration](#external-tool-integration)
  - [Jira Integration](#jira-integration)
  - [GitHub Integration](#github-integration)
  - [Webhook Integration](#webhook-integration)
- [CI/CD Integration](#cicd-integration)
  - [GitHub Actions Example](#github-actions-example)
  - [Jenkins Pipeline Example](#jenkins-pipeline-example)
- [Rate Limiting](#rate-limiting)
- [Webhooks](#webhooks)
  - [Webhook Events](#webhook-events)
  - [Webhook Payload Example](#webhook-payload-example)
  - [Webhook Security](#webhook-security)
- [Error Handling](#error-handling)
- [Support](#support)

## Overview

The OASIS REST API provides programmatic access to all OASIS functionality, enabling automation, external tool integration, and custom workflows.

## Quick Start

### Starting the API Server

```bash
# Using the CLI
oasis serve --host 0.0.0.0 --port 8000

# Using Python
python -m uvicorn src.oasis.api.app:app --host 0.0.0.0 --port 8000
```

### API Documentation

Once the server is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc
- **OpenAPI Spec**: http://localhost:8000/api/openapi.json

## Authentication

All API requests require authentication using an API key:

```bash
curl -H "X-API-Key: your-api-key-here" \
  http://localhost:8000/api/v1/projects
```

## Common Use Cases

### 1. Create a Project

```bash
curl -X POST http://localhost:8000/api/v1/projects \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "name": "Web App Pentest",
    "description": "Security assessment",
    "settings": {
      "target_scope": ["https://example.com/*"]
    }
  }'
```

### 2. List HTTP Flows

```bash
curl http://localhost:8000/api/v1/{project-id}/flows?limit=10 \
  -H "X-API-Key: your-api-key"
```

### 3. Start a Vulnerability Scan

```bash
curl -X POST http://localhost:8000/api/v1/scanner/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "project_id": "project-uuid",
    "enabled_checks": ["sql_injection", "xss", "csrf"],
    "scan_intensity": "normal"
  }'
```

### 4. Export Findings

```bash
curl http://localhost:8000/api/v1/{project-id}/findings \
  -H "X-API-Key: your-api-key" \
  > findings.json
```

## CLI Usage

OASIS provides a command-line interface for automation:

### Project Management

```bash
# Create a project
oasis project create "My Project" -s "https://example.com/*"

# List projects
oasis project list

# Get project info
oasis project info <project-id>
```

### Vulnerability Scanning

```bash
# Start a scan
oasis scan start <project-id> -c sql_injection -c xss

# Export findings
oasis export findings <project-id> -f json -o findings.json
```

## External Tool Integration

### Jira Integration

```python
from src.oasis.integrations import JiraIntegration

jira = JiraIntegration(
    jira_url="https://company.atlassian.net",
    username="user@company.com",
    api_token="your-api-token",
    project_key="SEC"
)

# Create Jira issue from finding
issue_key = jira.create_issue_from_finding(finding)
```

### GitHub Integration

```python
from src.oasis.integrations import GitHubIntegration

github = GitHubIntegration(
    repo_owner="company",
    repo_name="security",
    access_token="your-github-token"
)

# Create GitHub issue from finding
issue_number = github.create_issue_from_finding(finding)
```

### Webhook Integration

```python
from src.oasis.integrations import WebhookIntegration

webhook = WebhookIntegration(
    webhook_url="https://your-server.com/webhook",
    secret="your-webhook-secret"
)

# Send finding notification
webhook.send_finding_notification(finding)

# Send scan complete notification
webhook.send_scan_complete_notification(project_id, findings_count)
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run OASIS Scan
        run: |
          oasis project create "CI Scan" -s "https://staging.example.com/*"
          oasis scan start $PROJECT_ID -c sql_injection -c xss
          oasis export findings $PROJECT_ID -f json -o findings.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-findings
          path: findings.json
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    oasis project create "Jenkins Scan"
                    oasis scan start $PROJECT_ID
                    oasis export findings $PROJECT_ID -f xml -o findings.xml
                '''
            }
        }
        
        stage('Publish Results') {
            steps {
                archiveArtifacts artifacts: 'findings.xml'
            }
        }
    }
}
```

## Rate Limiting

API requests are rate-limited:
- **Authenticated**: 100 requests/minute
- **Unauthenticated**: 10 requests/minute

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640000000
```

## Webhooks

Configure webhooks to receive real-time notifications:

### Webhook Events

- `finding.created` - New vulnerability discovered
- `scan.completed` - Scan finished
- `collaborator.interaction` - Out-of-band interaction detected

### Webhook Payload Example

```json
{
  "event": "finding.created",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "id": "finding-uuid",
    "type": "sql_injection",
    "severity": "high",
    "title": "SQL Injection in login form",
    "description": "..."
  }
}
```

### Webhook Security

Webhooks include an HMAC signature for verification:

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)
```

## Error Handling

API errors follow standard HTTP status codes:

- `400` - Bad Request (invalid input)
- `401` - Unauthorized (missing/invalid API key)
- `404` - Not Found (resource doesn't exist)
- `429` - Too Many Requests (rate limit exceeded)
- `500` - Internal Server Error

Error response format:
```json
{
  "detail": "Error message",
  "status_code": 400
}
```

## Support

For API support and questions:
- Documentation: https://docs.oasis-pentest.org
- GitHub Issues: https://github.com/oasis/oasis/issues
- Email: team@oasis-pentest.org
---

**Last Updated**: January 05, 2026
