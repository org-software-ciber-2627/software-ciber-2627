from pydantic import BaseModel


class AuthenticatedUser(BaseModel):
    user_id: str | int | None = None
    username: str
    role: str
