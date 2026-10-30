from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configurations for AI Augmented SAST Auditor."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "ai-augmented-sast-auditor"
    APP_VERSION: str = "1.0.0"
    LOG_LEVEL: str = "INFO"

    # GGUF Model
    GGUF_MODEL_PATH: str = "/models/codellama-7b-instruct.Q4_K_M.gguf"
    LLM_API_BASE: str = "http://localhost:8080/v1"
    SEVERITY_FAIL_THRESHOLD: str = "HIGH"


settings = Settings()
