from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

class ActionResult(BaseModel):
    action_name: str  # ex: "block_ip", "lock_user", "notify_slack"
    target: str       # ex: "192.168.1.50"
    success: bool
    details: str

class BruteForcePlaybookOutput(BaseModel):
    execution_id: str
    incident_id: str
    status: str = Field(..., description="COMPLETED, FAILED ou PARTIAL")
    ip_reputation_score: Optional[int] = None
    actions_taken: List[ActionResult] = []
    executed_at: datetime
    summary: str