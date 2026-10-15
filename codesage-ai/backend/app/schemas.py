from pydantic import BaseModel, EmailStr, Field

class AuthInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class UserOut(BaseModel):
    id: int
    email: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut

class AnalyzeInput(BaseModel):
    code: str = Field(min_length=1, max_length=100_000)
    title: str = Field(default="Untitled review", max_length=200)

class ReviewOut(BaseModel):
    id: int
    title: str
    created_at: str
    findings: list[dict]
    code: str
