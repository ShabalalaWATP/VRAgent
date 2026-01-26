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
    # Default to Gemini 3 Flash Preview - latest and most capable flash model
    # Other options: gemini-2.5-flash, gemini-3-pro-preview (most capable)
    gemini_model_id: str = Field("gemini-3-flash-preview", validation_alias="GEMINI_MODEL_ID")
    
    # OpenAI API settings (optional fallback)
    openai_api_key: str = Field("", validation_alias="OPENAI_API_KEY")
    openai_model: str = Field("gpt-4", validation_alias="OPENAI_MODEL")
    openai_base_url: str = Field("https://api.openai.com/v1", validation_alias="OPENAI_BASE_URL")
    
    # Ghidra configuration (optional, for binary decompilation)
    ghidra_home: str = Field("", validation_alias="GHIDRA_HOME")
    ghidra_headless_path: str = Field("", validation_alias="GHIDRA_HEADLESS_PATH")
    environment: str = Field("development", validation_alias="ENVIRONMENT")
    
    # Authentication settings
    secret_key: str = Field("vragent-change-this-in-production-2024", validation_alias="SECRET_KEY")
    access_token_expire_minutes: int = Field(240, validation_alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(7, validation_alias="REFRESH_TOKEN_EXPIRE_DAYS")
    
    # Ollama settings for air-gapped environments
    ollama_url: str = Field("http://localhost:11434", validation_alias="OLLAMA_URL")
    ollama_model: str = Field("llama3.2", validation_alias="OLLAMA_MODEL")
    use_ollama: bool = Field(False, validation_alias="USE_OLLAMA")
    
    # NVD API key (optional - increases rate limits from 5/30s to 50/30s)
    # Get one at: https://nvd.nist.gov/developers/request-an-api-key
    nvd_api_key: str = Field("", validation_alias="NVD_API_KEY")
    
    # File upload settings
    # Increased to 2GB to support large binaries (firmware, game engines, containers)
    # Can be increased to 5GB via environment variable for very large files
    max_upload_size: int = Field(2 * 1024 * 1024 * 1024, validation_alias="MAX_UPLOAD_SIZE")  # 2GB default (was 100MB)
    upload_dir: str = Field("/tmp/uploads", validation_alias="UPLOAD_DIR")  # Base upload directory

    # MITM storage settings
    mitm_storage_dir: str = Field("backend/storage/mitm", validation_alias="MITM_STORAGE_DIR")
    mitm_max_entries: int = Field(5000, validation_alias="MITM_MAX_ENTRIES")

    # Reverse engineering signature settings
    yara_rules_path: str = Field("backend/yara_rules", validation_alias="YARA_RULES_PATH")
    capa_path: str = Field("capa", validation_alias="CAPA_PATH")
    enable_capa: bool = Field(True, validation_alias="ENABLE_CAPA")
    
    # OWASP ZAP settings
    zap_url: str = Field("http://zap:8080", validation_alias="ZAP_URL")  # ZAP daemon URL
    zap_api_key: str = Field("", validation_alias="ZAP_API_KEY")  # Empty = API key disabled
    
    # Scanner sidecar settings (for Dynamic Security Scanner)
    SCANNER_URL: str = Field("http://localhost:9999", validation_alias="SCANNER_URL")  # Scanner sidecar URL
    
    # LLM cost optimization settings
    max_embedding_chunks: int = Field(500, validation_alias="MAX_EMBEDDING_CHUNKS")  # Max chunks to embed
    max_llm_exploit_calls: int = Field(20, validation_alias="MAX_LLM_EXPLOIT_CALLS")  # Max LLM calls for exploits
    enable_embedding_cache: bool = Field(True, validation_alias="ENABLE_EMBEDDING_CACHE")  # Disk cache for embeddings
    skip_embeddings: bool = Field(False, validation_alias="SKIP_EMBEDDINGS")  # Skip embedding entirely (cheapest)
    
    # Large codebase handling settings
    max_source_files: int = Field(5000, validation_alias="MAX_SOURCE_FILES")  # Max files to process
    max_total_chunks: int = Field(5000, validation_alias="MAX_TOTAL_CHUNKS")  # Max code chunks
    max_chunks_per_file: int = Field(50, validation_alias="MAX_CHUNKS_PER_FILE")  # Max chunks per file
    chunk_flush_threshold: int = Field(500, validation_alias="CHUNK_FLUSH_THRESHOLD")  # DB flush threshold
    
    # Scanner settings for large codebases
    scanner_timeout: int = Field(600, validation_alias="SCANNER_TIMEOUT")  # Per-scanner timeout (10 min)
    max_parallel_scanners: int = Field(4, validation_alias="MAX_PARALLEL_SCANNERS")  # Parallel scanner limit
    max_concurrent_dynamic_scans: int = Field(2, validation_alias="MAX_CONCURRENT_DYNAMIC_SCANS")

    # Dynamic Scanner agentic loop settings
    dynamic_scan_agent_max_steps: int = Field(12, validation_alias="DYNAMIC_SCAN_AGENT_MAX_STEPS")
    dynamic_scan_agent_max_minutes: int = Field(45, validation_alias="DYNAMIC_SCAN_AGENT_MAX_MINUTES")
    dynamic_scan_agent_max_no_progress: int = Field(3, validation_alias="DYNAMIC_SCAN_AGENT_MAX_NO_PROGRESS")
    dynamic_scan_agent_action_timeout: int = Field(1200, validation_alias="DYNAMIC_SCAN_AGENT_ACTION_TIMEOUT")
    
    # Dynamic Scanner security settings
    allow_localhost_scans: bool = Field(False, validation_alias="ALLOW_LOCALHOST_SCANS")  # Enable for dev/testing
    allow_private_ip_scans: bool = Field(False, validation_alias="ALLOW_PRIVATE_IP_SCANS")  # Enable for internal networks
    
    # AI Analysis settings for large codebases
    max_findings_for_ai: int = Field(500, validation_alias="MAX_FINDINGS_FOR_AI")  # Max findings for AI analysis
    max_findings_for_llm: int = Field(50, validation_alias="MAX_FINDINGS_FOR_LLM")  # Max findings sent to LLM
    
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
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience accessor
settings = get_settings()
