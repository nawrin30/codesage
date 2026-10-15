from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./codesage.db"
    jwt_secret: str = "dev-only-change-this-secret"
    access_token_minutes: int = 60
    cors_origins: str = "http://localhost:5173"
    openai_api_key: str = ""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
