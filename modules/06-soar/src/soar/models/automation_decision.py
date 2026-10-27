from typing import Optional

from pydantic import BaseModel


class AutomationDecision(BaseModel):
    automatable: bool
    playbook: Optional[str] = None
    reason: str
