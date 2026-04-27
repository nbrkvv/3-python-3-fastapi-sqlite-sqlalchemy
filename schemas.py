from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)
    full_name: str = Field(min_length=2, max_length=120)
    secret_question: str | None = None
    secret_answer: str | None = None


class UserLogin(BaseModel):
    username: str
    password: str


class AuthorizationCheck(BaseModel):
    user_id: int
    object_name: str
    operation: str
    method: str
