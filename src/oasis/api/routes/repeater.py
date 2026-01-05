"""
Repeater API routes.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ...core.models import HTTPRequest, HTTPResponse


router = APIRouter()


class SendRequestModel(BaseModel):
    """Request model for sending HTTP requests."""

    request: HTTPRequest


class SendResponse(BaseModel):
    """Response model for sent requests."""

    request: HTTPRequest
    response: HTTPResponse | None
    duration_ms: int


@router.post("/send", response_model=SendResponse)
async def send_request(data: SendRequestModel):
    """
    Send an HTTP request via Repeater.

    Sends a custom HTTP request and returns the response.

    **Parameters:**
    - **request**: Complete HTTP request to send

    **Returns:**
    - Request, response, and timing information
    """
    # In a real implementation, this would actually send the request
    return SendResponse(request=data.request, response=None, duration_ms=0)
