"""
secure_app.py

Secure versions of patterns in `vuln_app.py` demonstrating safer alternatives.
"""
import os
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


# Not used demo Azure credentials (do not use in real environments)
DEMO_AZURE_CLIENT_ID = os.getenv("DEMO_AZURE_CLIENT_ID")
DEMO_AZURE_CLIENT_SECRET = os.getenv("DEMO_AZURE_CLIENT_SECRET")

# FAKE demo GitHub token (pattern only)
DEMO_GITHUB_TOKEN = os.getenv("DEMO_GITHUB_TOKEN")

def print_demo_secrets():
    """Prints truncated demo secrets to avoid leaking full strings in logs.

    Purpose: keep references so linters don't treat them as unused, and
    provide a simple runtime demonstration that these are present.
    """
    secrets = {
        "DEMO_AZURE_CLIENT_ID": DEMO_AZURE_CLIENT_ID,
        "DEMO_AZURE_CLIENT_SECRET": DEMO_AZURE_CLIENT_SECRET,
        "DEMO_GITHUB_TOKEN": DEMO_GITHUB_TOKEN,
    }
    for k, v in secrets.items():
        display = v[:10] if v else "(not set)"
        print(f"{k}: {display}... (demo)")


if __name__ == "__main__":
    print("SHA256 of 'password':", use_secure_hash("password"))
    print_demo_secrets()