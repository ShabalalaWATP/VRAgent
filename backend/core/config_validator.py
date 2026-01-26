"""
Configuration Validation for VRAgent
Validates configuration on startup to prevent runtime errors
"""

import os
import logging
from typing import List, Tuple, Optional
from pathlib import Path
import re

from backend.core.config import settings


logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    """Raised when configuration validation fails"""
    pass


class ConfigValidator:
    """
    Validates VRAgent configuration on startup.

    Features:
    - Database connectivity
    - Redis connectivity
    - File system permissions
    - API key validation
    - Resource limit sanity checks
    - Dependency availability
    """

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """
        Run all validation checks.

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        logger.info("Starting configuration validation...")

        # Core requirements (errors if fail)
        self.validate_database_url()
        self.validate_redis_url()
        self.validate_file_paths()
        self.validate_resource_limits()

        # Optional requirements (warnings if fail)
        self.validate_api_keys()
        self.validate_ghidra()
        self.validate_secret_key()

        # Check if valid
        is_valid = len(self.errors) == 0

        if is_valid:
            logger.info("✅ Configuration validation passed")
        else:
            logger.error(f"❌ Configuration validation failed with {len(self.errors)} errors")

        if self.warnings:
            logger.warning(f"⚠️  {len(self.warnings)} warnings found")

        return is_valid, self.errors, self.warnings

    def validate_database_url(self):
        """Validate DATABASE_URL configuration"""
        if not settings.database_url:
            self.errors.append("DATABASE_URL is not set")
            return

        url = str(settings.database_url)

        # Check format
        if not url.startswith(('postgresql://', 'postgresql+asyncpg://')):
            self.errors.append(f"DATABASE_URL must start with postgresql:// or postgresql+asyncpg://")
            return

        # Check has required components
        if '@' not in url or '/' not in url:
            self.errors.append("DATABASE_URL appears malformed (missing credentials or database name)")

        logger.debug("✅ DATABASE_URL format is valid")

    def validate_redis_url(self):
        """Validate REDIS_URL configuration"""
        if not settings.redis_url:
            self.errors.append("REDIS_URL is not set")
            return

        url = settings.redis_url

        # Check format
        if not url.startswith('redis://'):
            self.errors.append("REDIS_URL must start with redis://")
            return

        logger.debug("✅ REDIS_URL format is valid")

    def validate_file_paths(self):
        """Validate file system paths and permissions"""
        # Upload directory
        upload_dir = settings.upload_dir

        if not os.path.exists(upload_dir):
            try:
                os.makedirs(upload_dir, exist_ok=True)
                logger.debug(f"✅ Created upload directory: {upload_dir}")
            except Exception as e:
                self.errors.append(f"Cannot create upload directory {upload_dir}: {e}")
                return

        # Check write permissions
        if not os.access(upload_dir, os.W_OK):
            self.errors.append(f"Upload directory {upload_dir} is not writable")

        # Check read permissions
        if not os.access(upload_dir, os.R_OK):
            self.errors.append(f"Upload directory {upload_dir} is not readable")

        # Log directory
        log_dir = Path("logs")
        if not log_dir.exists():
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
                logger.debug(f"✅ Created log directory: {log_dir}")
            except Exception as e:
                self.warnings.append(f"Cannot create log directory: {e}")

        logger.debug("✅ File paths validated")

    def validate_resource_limits(self):
        """Validate resource limit configuration"""
        # Max upload size
        max_upload = settings.max_upload_size

        if max_upload <= 0:
            self.errors.append("max_upload_size must be positive")

        if max_upload > 10 * 1024 * 1024 * 1024:  # 10GB
            self.warnings.append(f"max_upload_size is very large: {max_upload / (1024**3):.2f}GB")

        # Check if upload size is reasonable for available disk
        try:
            import psutil
            disk = psutil.disk_usage(settings.upload_dir)
            free_gb = disk.free / (1024 ** 3)
            upload_gb = max_upload / (1024 ** 3)

            if upload_gb > free_gb * 0.5:
                self.warnings.append(
                    f"max_upload_size ({upload_gb:.2f}GB) is more than 50% of free disk space ({free_gb:.2f}GB)"
                )
        except Exception as e:
            logger.debug(f"Could not check disk space: {e}")

        logger.debug("✅ Resource limits validated")

    def validate_api_keys(self):
        """Validate API keys (warnings only)"""
        # Gemini API key
        if not settings.gemini_api_key:
            self.warnings.append("GEMINI_API_KEY not set - AI features will be limited")
        elif len(settings.gemini_api_key) < 10:
            self.warnings.append("GEMINI_API_KEY appears too short")

        # OpenAI API key
        if not settings.openai_api_key:
            self.warnings.append("OPENAI_API_KEY not set - AI features will be limited")
        elif not settings.openai_api_key.startswith('sk-'):
            self.warnings.append("OPENAI_API_KEY does not start with 'sk-' (may be invalid)")

        # At least one AI service should be configured
        if not settings.gemini_api_key and not settings.openai_api_key:
            self.warnings.append("No AI service configured - AI features will be unavailable")

        logger.debug("✅ API keys validated")

    def validate_ghidra(self):
        """Validate Ghidra configuration (warnings only)"""
        ghidra_home = settings.ghidra_home

        if not ghidra_home:
            self.warnings.append("GHIDRA_HOME not set - decompilation will be unavailable")
            return

        # Check directory exists
        if not os.path.isdir(ghidra_home):
            self.warnings.append(f"GHIDRA_HOME directory does not exist: {ghidra_home}")
            return

        # Check for analyzeHeadless script
        analyze_script = os.path.join(ghidra_home, "support", "analyzeHeadless")
        if os.name == 'nt':
            analyze_script += ".bat"

        if not os.path.isfile(analyze_script):
            self.warnings.append(
                f"Ghidra analyzeHeadless script not found at {analyze_script}"
            )

        logger.debug("✅ Ghidra configuration validated")

    def validate_secret_key(self):
        """Validate SECRET_KEY configuration"""
        secret_key = settings.secret_key

        if not secret_key:
            self.errors.append("SECRET_KEY is not set")
            return

        # Check length
        if len(secret_key) < 32:
            self.warnings.append("SECRET_KEY is too short (should be at least 32 characters)")

        # Check if using default/weak key
        weak_keys = [
            "secret",
            "password",
            "changeme",
            "vragent",
            "dev",
            "development"
        ]

        secret_lower = secret_key.lower()
        for weak in weak_keys:
            if weak in secret_lower:
                if settings.environment == "production":
                    self.errors.append(f"SECRET_KEY appears weak in production (contains '{weak}')")
                else:
                    self.warnings.append(f"SECRET_KEY appears weak (contains '{weak}')")

        logger.debug("✅ SECRET_KEY validated")

    def validate_environment(self):
        """Validate environment-specific settings"""
        env = settings.environment

        if env == "production":
            # Production-specific checks
            if settings.secret_key and "dev" in settings.secret_key.lower():
                self.errors.append("Using development SECRET_KEY in production")

            # Check database URL doesn't contain 'localhost'
            if "localhost" in str(settings.database_url):
                self.warnings.append("DATABASE_URL points to localhost in production")

        elif env == "development":
            # Development-specific checks
            if settings.database_url and "production" in str(settings.database_url):
                self.warnings.append("DATABASE_URL appears to point to production database")

        logger.debug(f"✅ Environment '{env}' validated")


def validate_config_or_exit():
    """
    Validate configuration and exit if invalid.

    Call this at application startup.
    """
    validator = ConfigValidator()
    is_valid, errors, warnings = validator.validate_all()

    # Print errors
    if errors:
        print("\n❌ Configuration Errors:")
        for error in errors:
            print(f"  - {error}")

    # Print warnings
    if warnings:
        print("\n⚠️  Configuration Warnings:")
        for warning in warnings:
            print(f"  - {warning}")

    # Exit if invalid
    if not is_valid:
        print("\n❌ Configuration validation failed. Please fix errors and restart.")
        exit(1)

    # Success
    if not warnings:
        print("\n✅ Configuration validation passed")
    else:
        print(f"\n✅ Configuration validation passed with {len(warnings)} warnings")


def check_dependency(command: str, name: str) -> bool:
    """
    Check if a system dependency is available.

    Args:
        command: Command to check (e.g., 'docker', 'git')
        name: Human-readable name

    Returns:
        bool: True if available
    """
    import shutil

    if shutil.which(command):
        logger.debug(f"✅ {name} is available")
        return True
    else:
        logger.warning(f"⚠️  {name} is not available")
        return False


def validate_dependencies():
    """Validate optional system dependencies"""
    dependencies = {
        'docker': 'Docker',
        'git': 'Git',
        'adb': 'Android Debug Bridge',
    }

    available = {}
    for cmd, name in dependencies.items():
        available[cmd] = check_dependency(cmd, name)

    return available


# ============================================================================
# Configuration Health Check
# ============================================================================

def get_config_health() -> dict:
    """
    Get configuration health status for monitoring.

    Returns:
        dict: Configuration health information
    """
    validator = ConfigValidator()
    is_valid, errors, warnings = validator.validate_all()

    return {
        "valid": is_valid,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "errors": errors,
        "warnings": warnings,
        "environment": settings.environment,
        "features": {
            "database": bool(settings.database_url),
            "redis": bool(settings.redis_url),
            "ai_gemini": bool(settings.gemini_api_key),
            "ai_openai": bool(settings.openai_api_key),
            "ghidra": bool(settings.ghidra_home),
        }
    }


if __name__ == "__main__":
    # Run validation when executed directly
    validate_config_or_exit()
