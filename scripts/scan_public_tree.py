"""Fail-closed allowlist scanner for the proposed public source tree."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_ROOT_FILES = {"README.md", "LICENSE", ".gitignore"}
ALLOWED_DIRS = {"public", "gateway", "schemas", "scripts", "tests", "cloudflared"}
ALLOWED_SUFFIXES = {".html", ".css", ".js", ".json", ".py", ".ps1", ".yml", ".md", ".gitignore"}
FORBIDDEN_NAME = re.compile(r"(^|[._-])(db|sqlite|env|pem|key|p12|secret|credential|password|hash)([._-]|$)", re.I)
FORBIDDEN_CONTENT = [
    re.compile(r"(?<![#A-Fa-f0-9])\d{6,}(?![A-Fa-f0-9])"),
    re.compile(r"pbkdf2_sha256\$\d+\$[A-Za-z0-9_-]+=*\$[A-Za-z0-9_-]+=*"),
    re.compile(r"\b(?:password|secret|token|api[_-]?key)\b\s*=\s*['\"](?!<)[A-Za-z0-9_./+=:-]{16,}['\"]", re.I),
]


def scan() -> list[str]:
    errors: list[str] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if relative.parts[0] in {".git", "__pycache__"} or "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if len(relative.parts) == 1:
            if relative.name not in ALLOWED_ROOT_FILES:
                errors.append(f"root file outside allowlist: {relative}")
        elif relative.parts[0] not in ALLOWED_DIRS:
            errors.append(f"directory outside allowlist: {relative}")
        if path.name not in {".gitignore", "LICENSE"} and path.suffix.lower() not in ALLOWED_SUFFIXES:
            errors.append(f"file type outside allowlist: {relative}")
        if FORBIDDEN_NAME.search(path.name):
            # The source code is allowed to contain password-handling symbols;
            # filenames still cannot claim to contain credentials or hashes.
            if path.name.lower() not in {"make_password_hash.py"}:
                errors.append(f"sensitive filename: {relative}")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"non-text file: {relative}")
            continue
        for pattern in FORBIDDEN_CONTENT:
            if pattern.search(text):
                errors.append(f"sensitive content pattern {pattern.pattern!r}: {relative}")
    return errors


def main() -> int:
    errors = scan()
    if errors:
        print("PUBLIC TREE REJECTED")
        print("\n".join(errors))
        return 1
    files = [path.relative_to(ROOT).as_posix() for path in sorted(ROOT.rglob("*")) if path.is_file() and "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}]
    print("PUBLIC TREE ACCEPTED")
    print("Allowlisted files:")
    print("\n".join(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
