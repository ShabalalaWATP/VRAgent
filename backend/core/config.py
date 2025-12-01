import os
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class Settings(BaseSettings):
    """Application configuration settings loaded from environment variables."""
    
    database_url: str = Field(..., validation_alias="DATABASE_URL")
    redis_url: str = Field(..., validation_alias="REDIS_URL")
    gemini_api_key: str = Field("", validation_alias="GEMINI_API_KEY")
    gemini_model_id: str = Field("gemini-pro", validation_alias="GEMINI_MODEL_ID")
    environment: str = Field("development", validation_alias="ENVIRONMENT")
    
    # NVD API key (optional - increases rate limits from 5/30s to 50/30s)
    # Get one at: https://nvd.nist.gov/developers/request-an-api-key
    nvd_api_key: str = Field("", validation_alias="NVD_API_KEY")
    
    # File upload settings
    max_upload_size: int = Field(100 * 1024 * 1024, validation_alias="MAX_UPLOAD_SIZE")  # 100MB default
    
    # LLM cost optimization settings
    max_embedding_chunks: int = Field(500, validation_alias="MAX_EMBEDDING_CHUNKS")  # Max chunks to embed
    max_llm_exploit_calls: int = Field(20, validation_alias="MAX_LLM_EXPLOIT_CALLS")  # Max LLM calls for exploits
    enable_embedding_cache: bool = Field(True, validation_alias="ENABLE_EMBEDDING_CACHE")  # Disk cache for embeddings
    skip_embeddings: bool = Field(False, validation_alias="SKIP_EMBEDDINGS")  # Skip embedding entirely (cheapest)
    
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment is one of the allowed values."""
        allowed = {"development", "test", "production"}
        if v.lower() not in allowed:
            raise ValueError(f"Environment must be one of: {allowed}")
        return v.lower()

    class Config:
        case_sensitive = False
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience accessor
settings = get_settings()
