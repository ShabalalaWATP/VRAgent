"""
Centralized logging configuration for VRAgent backend.
"""
import logging
import sys
from typing import Optional

from .config import settings


def setup_logging(level: Optional[str] = None) -> logging.Logger:
    """
    Configure and return the root logger for the application.
    
    Args:
        level: Optional log level override (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Configured logger instance
    """
    log_level = level or ("DEBUG" if settings.environment == "development" else "INFO")
    
    # Create formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger("vragent")
    root_logger.setLevel(getattr(logging, log_level.upper()))
    root_logger.addHandler(console_handler)
    
    # Prevent duplicate logs
    root_logger.propagate = False
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Module name for the logger
    
    Returns:
        Logger instance
    """
    return logging.getLogger(f"vragent.{name}")


# Initialize default logger
logger = setup_logging()
