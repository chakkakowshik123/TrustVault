"""File validation, magic bytes verification, and secure storage."""
import os
import re
import uuid
from pathlib import Path
from typing import Tuple

from .config import settings

# Dangerous executable extensions that are unconditionally rejected
BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".bash", ".php", ".phtml", ".py", ".pyw",
    ".pl", ".cgi", ".js", ".vbs", ".ps1", ".psm1", ".msi", ".dll", ".so",
    ".com", ".scr", ".jar", ".wsf", ".hta", ".asp", ".aspx", ".jsp", ".bin"
}

# Supported magic byte signatures
MAGIC_SIGNATURES = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".docx": [b"PK\x03\x04"],
    ".xlsx": [b"PK\x03\x04"],
    ".zip": [b"PK\x03\x04"],
}


def sanitize_filename(filename: str) -> str:
    """Strip directory traversal sequences and invalid characters."""
    base = os.path.basename(filename)
    clean = re.sub(r"[^\w\s\.-]", "_", base).strip()
    return clean or f"file_{uuid.uuid4().hex[:8]}.bin"


def validate_file_content(filename: str, content: bytes) -> Tuple[bool, str, str]:
    """
    Validate file size, extension, and magic bytes.
    Returns: (is_valid, error_message, detected_mime_type)
    """
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if len(content) > max_bytes:
        return False, f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_MB} MB.", ""

    if len(content) == 0:
        return False, "File is completely empty.", ""

    clean_name = sanitize_filename(filename)
    ext = Path(clean_name).suffix.lower()

    if ext in BLOCKED_EXTENSIONS:
        return False, f"Executable or script files ({ext}) are strictly prohibited.", ""

    # Magic byte verification
    if ext in MAGIC_SIGNATURES:
        signatures = MAGIC_SIGNATURES[ext]
        if not any(content.startswith(sig) for sig in signatures):
            return False, f"File magic bytes mismatch: {clean_name} is not a valid {ext} file.", ""

    # Text / Document validation
    if ext in (".txt", ".md", ".csv", ".json", ".log"):
        # Ensure text files do not contain embedded null bytes (common indicator of hidden shellcode/binaries)
        if b"\x00" in content[:4096]:
            return False, f"Binary or null bytes detected in text file {clean_name}.", ""

    # Map safe MIME types
    mime_map = {
        ".pdf": "application/pdf",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".zip": "application/zip",
        ".txt": "text/plain; charset=utf-8",
        ".md": "text/markdown; charset=utf-8",
        ".csv": "text/csv; charset=utf-8",
        ".json": "application/json",
    }
    mime_type = mime_map.get(ext, "application/octet-stream")

    return True, "", mime_type


def save_secure_file(filename: str, content: bytes) -> Tuple[str, str]:
    """
    Save file to private storage outside web root with randomized UUID name.
    Returns: (sanitized_original_filename, stored_name)
    """
    clean_original = sanitize_filename(filename)
    ext = Path(clean_original).suffix.lower()
    stored_name = f"{uuid.uuid4().hex}{ext}"

    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    target_path = settings.UPLOAD_DIR / stored_name

    with open(target_path, "wb") as f:
        f.write(content)

    return clean_original, stored_name
