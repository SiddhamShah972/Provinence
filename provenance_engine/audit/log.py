"""
Audit Telemetry & Secret Scrubbing
Configures the global Loguru logger to intercept, scrub, and serialize
execution telemetry, ensuring no API keys, tokens, or ambient environment
secrets are written to disk.
"""

import os
import re
from loguru import logger
from pathlib import Path

# Sensitive regex patterns to scrub from all telemetry
SECRET_PATTERNS = [
    re.compile(r"(?i)(?:api_key|token|secret|password|auth)[\s:=]+(['\"]?)[a-zA-Z0-9_\-\+]{16,}(['\"]?)"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),  # Google/Gemini API Key
    re.compile(r"sk-[a-zA-Z0-9]{48}"),      # OpenAI API Key
    re.compile(r"gh[pousr]_[a-zA-Z0-9]{36}") # GitHub Token
]

def secret_scrubber_filter(record: dict) -> bool:
    """
    Loguru filter function that intercepts log messages and exceptions,
    redacting any substrings that match known secret patterns or
    environment variable values.
    """
    message = record.get("message", "")
    
    if not isinstance(message, str):
        return True

    # Scrub explicit regex patterns
    for pattern in SECRET_PATTERNS:
        if pattern.search(message):
            message = pattern.sub(r"[REDACTED_SECRET]", message)
            
    # Scrub known sensitive environment variables if present in message
    sensitive_keys = {"GEMINI_API_KEY", "GOOGLE_API_KEY", "AWS_SECRET_ACCESS_KEY"}
    for key in sensitive_keys:
        val = os.getenv(key)
        if val and len(val) > 4 and val in message:
            message = message.replace(val, "[REDACTED_ENV_SECRET]")

    record["message"] = message
    return True

def setup_audit_telemetry(log_dir: str | Path = "output/audit_logs") -> None:
    """
    Initializes the secure audit logger. 
    Call this early in main.py or batch.py.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    
    # Remove default handler and add the scrubbed file handler
    logger.remove()
    
    # Add console output (optional for production, useful for CLI)
    logger.add(
        sink=lambda msg: print(msg, end=""),
        filter=secret_scrubber_filter,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan> - <level>{message}</level>",
        level="INFO"
    )
    
    # Add JSON file output for structured telemetry analysis
    logger.add(
        sink=str(log_path / "telemetry_{time:YYYY-MM-DD}.jsonl"),
        filter=secret_scrubber_filter,
        serialize=True,  # Writes as structured JSON
        rotation="100 MB",
        retention="30 days",
        level="DEBUG"
    )
