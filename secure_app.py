"""
secure_app.py

Secure versions of patterns in `vuln_app.py` demonstrating safer alternatives.
"""
import subprocess
import hashlib


ALLOWED_COMMANDS = {"echo", "ls", "cat"}


def safe_eval(expr: str):
    """Safer limited evaluation — using literal_eval to avoid arbitrary code execution."""
    from ast import literal_eval

    try:
        return literal_eval(expr)
    except Exception:
        raise ValueError("Expression not allowed")


def run_shell_command_safe(args: list) -> subprocess.CompletedProcess:
    """Run a command safely. args must be a list; the executable must be in ALLOWED_COMMANDS."""
    if not isinstance(args, list) or not args:
        raise ValueError("args must be a non-empty list")
    if args[0] not in ALLOWED_COMMANDS:
        raise ValueError(f"Command '{args[0]}' is not permitted")
    return subprocess.run(args, shell=False)


def use_secure_hash(value: str) -> str:
    """Use SHA-256 for hashing (not for password storage, but stronger than MD5)."""
    return hashlib.sha256(value.encode()).hexdigest()


if __name__ == "__main__":
    print("SHA256 of 'password':", use_secure_hash("password"))
