"""
SafeExec: Parameterized CLI & Git Execution Isolation Sandbox
Enforces zero-shell subprocess invocation, binary allowlisting, argument sanitization,
and environment credential scrubbing.
"""

import asyncio
import os
import shutil
from typing import List, Dict, Optional, Tuple
from loguru import logger

from config.settings import settings


class ExecutionSecurityError(Exception):
    """Raised when an execution violates allowlist, argument, or environment boundaries."""
    pass


# Alias for OSINT and runner security checks
SubprocessSecurityException = ExecutionSecurityError


class ExecutionTimeoutError(Exception):
    """Raised when a subprocess exceeds execution time quotas."""
    pass


class CommandExecutionError(Exception):
    """Raised on non-zero exit code or process execution failure."""
    pass


class SafeExec:
    # Environment keys that must never leak to spawned child processes
    SENSITIVE_ENV_KEYS = {
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "SSH_AUTH_SOCK",
        "PRIVATE_KEY",
    }

    # Shell injection metacharacters rejected in raw argument tokens
    SHELL_METACHARS = {";", "&", "|", "`", "$", "\n", "\r", ">", "<"}

    @classmethod
    def sanitize_environment(cls, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Creates a scrubbed environment stripped of ambient sensitive credentials."""
        clean_env = {
            k: v for k, v in os.environ.items() if k not in cls.SENSITIVE_ENV_KEYS
        }
        if custom_env:
            for k, v in custom_env.items():
                if k not in cls.SENSITIVE_ENV_KEYS:
                    clean_env[k] = v
        return clean_env

    @classmethod
    def validate_command(cls, binary: str, args: List[str]) -> str:
        """Validates that binary is allowlisted and arguments contain no shell metacharacters."""
        bin_base = os.path.basename(binary).lower().removesuffix(".exe")

        if bin_base not in settings.allowed_exec_binaries:
            raise ExecutionSecurityError(
                f"Binary '{binary}' (resolved: '{bin_base}') is not in allowed execution list: {settings.allowed_exec_binaries}"
            )

        resolved_path = shutil.which(binary)
        if not resolved_path:
            raise ExecutionSecurityError(f"Binary '{binary}' could not be located in system PATH.")

        # Inspect argument tokens
        for arg in args:
            for char in cls.SHELL_METACHARS:
                if char in arg:
                    raise ExecutionSecurityError(
                        f"Argument token '{arg}' contains prohibited shell metacharacter '{char}'."
                    )

        return resolved_path

    @classmethod
    async def run(
        cls,
        binary: str,
        args: List[str],
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        custom_env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str]:
        """Executes binary asynchronously strictly without a shell."""
        resolved_bin = cls.validate_command(binary, args)
        clean_env = cls.sanitize_environment(custom_env)
        cmd_timeout = timeout or settings.exec_timeout_seconds

        try:
            # shell=False is enforced by create_subprocess_exec
            proc = await asyncio.create_subprocess_exec(
                resolved_bin,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=clean_env,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=cmd_timeout,
            )

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                logger.warning(f"Command '{binary}' exited with code {proc.returncode}. Stderr: {stderr[:200]}")

            return proc.returncode, stdout, stderr

        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            raise ExecutionTimeoutError(f"Process '{binary}' timed out after {cmd_timeout} seconds.")
        except (ExecutionSecurityError, ExecutionTimeoutError):
            raise
        except Exception as e:
            raise CommandExecutionError(f"Failed to execute command '{binary}': {str(e)}") from e


class HardenedSubprocessRunner:
    """Enforces strict regex allowlists for arguments to prevent CLI injection."""
    import re
    HANDLE_PATTERN = re.compile(r"^[a-zA-Z0-9_\.]{1,64}$")
    DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
    DISALLOWED_CHARS = {";", "&", "|", "`", "$", "\0", "\n", "\r", "<", ">", " ", "/", "\\"}

    @classmethod
    def validate_arg(cls, value: str, arg_type: str) -> str:
        if not value or not isinstance(value, str):
            raise SubprocessSecurityException(f"Argument '{value}' is not a valid non-empty string.")

        # Flag injection
        if value.startswith("-"):
            raise SubprocessSecurityException(f"Flag injection detected in {arg_type}: '{value}'")

        # Prohibited shell characters and null bytes
        for c in cls.DISALLOWED_CHARS:
            if c in value:
                raise SubprocessSecurityException(f"Prohibited character '{c}' in {arg_type}: '{value}'")

        if arg_type == "handle":
            if not cls.HANDLE_PATTERN.fullmatch(value):
                raise SubprocessSecurityException(f"Handle '{value}' violates regex allowlist.")
            return value

        elif arg_type == "domain":
            if "*" in value or ".." in value:
                raise SubprocessSecurityException(f"Wildcards or traversal prohibited in domain: '{value}'")
            if not cls.DOMAIN_PATTERN.fullmatch(value):
                raise SubprocessSecurityException(f"Domain '{value}' violates strict DNS format allowlist.")
            return value

        return value

