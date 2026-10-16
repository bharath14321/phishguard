"""
Email Attachment Analyzer

Safely performs STATIC analysis of email attachments.

It checks:
- Filename
- Extension
- MIME type
- File size
- Magic/signature bytes
- SHA-256 hash
- Potential macro-enabled Office files
- Suspicious extensions

IMPORTANT:
This module DOES NOT execute attachments.
Dynamic malware analysis will be handled later inside
an isolated sandbox.
"""

import hashlib
import mimetypes
from pathlib import Path


# Extensions that deserve additional inspection.
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".hta",
    ".msi",
    ".jar",
    ".iso",
    ".img",
    ".lnk",
}

# Microsoft Office formats capable of containing VBA macros.
MACRO_ENABLED_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".pptm",
    ".potm",
    ".ppsm",
}

# Standard document extensions that can be inspected for embedded macros
INSPECTABLE_OFFICE_EXTENSIONS = {
    ".docx",
    ".xlsx",
    ".pptx",
    ".doc",
    ".xls",
    ".ppt",
}

# Plain-text, media, and archive formats where VBA macro execution is not applicable
NON_MACRO_EXTENSIONS = {
    ".txt", ".csv", ".log", ".json", ".xml", ".yaml", ".yml",
    ".html", ".htm", ".css", ".js", ".ts",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".bmp", ".webp", ".ico", ".tiff",
    ".mp3", ".wav", ".ogg", ".mp4", ".mov", ".avi", ".mkv",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".pdf",
}

import zipfile


def inspect_macro_status(file_path: str, extension: str = "", mime_type: str = "") -> tuple[str, str, bool]:
    """Inspect file for VBA macros and return (status, details, has_macros).

    Distinguishes:
    - NOT_APPLICABLE: Plain-text, images, media, or non-compound formats
    - NO_MACROS_FOUND: Document inspected and confirmed free of VBA streams
    - MACROS_DETECTED: Document contains macro-enabled headers or vbaProject.bin
    - NOT_ANALYZED: Unknown or unsupported file type
    - ERROR: Archive or inspection failure
    """
    ext = (extension or Path(file_path).suffix).lower().strip()
    mime = (mime_type or "").lower().strip()

    # 1. Plain-text and non-document formats
    if ext in NON_MACRO_EXTENSIONS or mime.startswith("text/") or mime.startswith("image/") or mime.startswith("audio/") or mime.startswith("video/"):
        desc = "Not applicable — plain-text file" if ext in (".txt", ".csv", ".log") or mime == "text/plain" else f"Not applicable for {ext or 'this'} format"
        return "NOT_APPLICABLE", desc, False

    # 2. Explicit macro-enabled Office formats (.docm, .xlsm, .pptm, etc.)
    if ext in MACRO_ENABLED_EXTENSIONS:
        return "MACROS_DETECTED", "Macro-enabled Office document format", True

    # 3. OpenXML formats (.docx, .xlsx, .pptx) - inspect zip structure for vbaProject.bin
    if ext in (".docx", ".xlsx", ".pptx"):
        try:
            if not zipfile.is_zipfile(file_path):
                return "NO_MACROS_FOUND", "Standard Office document format (no macro archive)", False
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = [n.lower() for n in zf.namelist()]
                has_vba = any("vbaproject.bin" in n or "vba/" in n for n in namelist)
                if has_vba:
                    return "MACROS_DETECTED", "VBA macro project archive (vbaProject.bin) detected inside document", True
                return "NO_MACROS_FOUND", "Document archive inspected; no VBA macros found", False
        except Exception as z_err:
            return "ERROR", f"Macro inspection error: {z_err}", False

    # 4. Legacy binary Office formats (.doc, .xls, .ppt)
    if ext in (".doc", ".xls", ".ppt"):
        try:
            with open(file_path, "rb") as bf:
                header = bf.read(65536)
                if b"_VBA_PROJECT" in header or b"VBA" in header or b"Macros" in header:
                    return "MACROS_DETECTED", "VBA macro stream signature detected in compound binary file", True
                return "NO_MACROS_FOUND", "Legacy Office binary inspected; no macro streams detected", False
        except Exception as o_err:
            return "ERROR", f"Binary inspection error: {o_err}", False

    # 5. Unsupported / unanalyzed
    return "NOT_ANALYZED", "File type not eligible for macro inspection", False


def calculate_sha256(file_path):
    """
    Calculate the SHA-256 hash of a file.

    The file is read in chunks so that large attachments
    do not need to be loaded completely into memory.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            # Read a manageable chunk.
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest().lower()


def get_file_signature(file_path):
    """
    Read the first few bytes of a file.

    Magic/signature bytes help determine the actual
    file type instead of trusting only the extension.
    """

    with open(file_path, "rb") as file:
        return file.read(16)


def detect_file_type(file_path):
    """
    Determine basic file information using the filename
    and MIME-type database.
    """

    path = Path(file_path)

    extension = path.suffix.lower()

    mime_type, _ = mimetypes.guess_type(
        path.name
    )

    return {
        "filename": path.name,
        "extension": extension,
        "mime_type": mime_type or "unknown",
    }


def analyze_attachment(file_path):
    """
    Perform complete static attachment analysis.

    No code from the attachment is executed.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    # Get basic file metadata.
    file_info = detect_file_type(
        file_path
    )

    # Determine file size in bytes.
    file_size = path.stat().st_size

    # Calculate cryptographic hash.
    sha256 = calculate_sha256(
        file_path
    )

    # Read magic/signature bytes.
    signature = get_file_signature(
        file_path
    )

    extension = file_info["extension"]
    mime_type = file_info["mime_type"]

    macro_status, macro_details, has_vba = inspect_macro_status(
        file_path, extension, mime_type
    )

    return {
        "filename": file_info["filename"],
        "extension": extension,
        "mime_type": mime_type,
        "size_bytes": file_size,
        "sha256": sha256,

        # Store the signature in hexadecimal form
        # for later file-type identification.
        "magic_bytes": signature.hex(),

        # Flag potentially dangerous extensions.
        "suspicious_extension": (
            extension in SUSPICIOUS_EXTENSIONS
        ),

        # Differentiated macro evaluation status
        "macro_status": macro_status,
        "macro_details": macro_details,
        "macro_enabled": has_vba,
        "has_vba_macros": has_vba,
    }


def main():
    """
    Test the attachment analyzer.

    Change TEST_FILE to an attachment available
    in your project.
    """

    TEST_FILE = "data/raw/test_attachment.pdf"

    result = analyze_attachment(
        TEST_FILE
    )

    print("\n========== ATTACHMENT ANALYSIS ==========")

    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
