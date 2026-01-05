"""
Intruder API routes.
"""

from typing import List
from fastapi import APIRouter
from pydantic import BaseModel

from ...intruder.config import AttackType
from ...core.models import HTTPRequest


router = APIRouter()


class AttackRequest(BaseModel):
    """Request model for Intruder attacks."""

    base_request: HTTPRequest
    attack_type: AttackType
    injection_points: List[str]
    payloads: List[str]


class AttackResponse(BaseModel):
    """Response model for attack results."""

    total_requests: int
    completed: int
    successful_payloads: List[str]


@router.post("/attack", response_model=AttackResponse)
async def start_attack(attack_request: AttackRequest):
    """
    Start an Intruder attack.

    Executes an automated attack with specified payloads.

    **Parameters:**
    - **base_request**: Base HTTP request template
    - **attack_type**: Type of attack (sniper, battering_ram, pitchfork, cluster_bomb)
    - **injection_points**: List of parameter names to inject payloads
    - **payloads**: List of payloads to test

    **Returns:**
    - Attack results with successful payloads
    """
    # In a real implementation, this would execute the attack
    return AttackResponse(
        total_requests=len(attack_request.payloads), completed=0, successful_payloads=[]
    )
