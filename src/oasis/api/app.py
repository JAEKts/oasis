"""
OASIS FastAPI Application

Main FastAPI application with OpenAPI documentation.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from ..core.config import OASISConfig


def create_app(config: OASISConfig = None) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        config: Optional OASIS configuration

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="OASIS API",
        description="Open Architecture Security Interception Suite REST API",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routes
    from .routes import projects, flows, findings, scanner, repeater, intruder

    app.include_router(projects.router, prefix="/api/v1/projects", tags=["projects"])
    app.include_router(flows.router, prefix="/api/v1/flows", tags=["flows"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
    app.include_router(scanner.router, prefix="/api/v1/scanner", tags=["scanner"])
    app.include_router(repeater.router, prefix="/api/v1/repeater", tags=["repeater"])
    app.include_router(intruder.router, prefix="/api/v1/intruder", tags=["intruder"])

    # Health check endpoint
    @app.get("/api/health", tags=["health"])
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "version": "0.1.0"}

    # Custom OpenAPI schema
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title="OASIS API",
            version="0.1.0",
            description="""
# OASIS REST API

The OASIS REST API provides programmatic access to all OASIS functionality for automation and external tool integration.

## Features

- **Project Management**: Create, update, and manage penetration testing projects
- **Traffic Analysis**: Access captured HTTP/HTTPS traffic flows
- **Vulnerability Scanning**: Trigger and retrieve vulnerability scan results
- **Request Manipulation**: Send and modify HTTP requests via Repeater
- **Automated Attacks**: Configure and execute Intruder attacks
- **Data Export**: Export findings and reports in various formats

## Authentication

API authentication is handled via API keys. Include your API key in the `X-API-Key` header:

```
X-API-Key: your-api-key-here
```

## Rate Limiting

API requests are rate-limited to prevent abuse. Current limits:
- 100 requests per minute for authenticated users
- 10 requests per minute for unauthenticated users

## Webhooks

OASIS supports webhooks for real-time notifications:
- New vulnerability findings
- Scan completion
- Collaborator interactions

Configure webhooks in your project settings.
            """,
            routes=app.routes,
        )

        # Add security scheme
        openapi_schema["components"]["securitySchemes"] = {
            "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
        }

        # Add security requirement to all endpoints
        for path in openapi_schema["paths"].values():
            for operation in path.values():
                if isinstance(operation, dict):
                    operation["security"] = [{"ApiKeyAuth": []}]

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi

    return app


# Create default app instance
app = create_app()


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """
    Run the OASIS API server.

    Args:
        host: Server host address
        port: Server port number
    """
    import uvicorn

    uvicorn.run(app, host=host, port=port)
