"""
attachment_scanner.py
----------------------
Attachment inspection — entirely absent from the original 8-stage pipeline
despite malicious attachments being one of the most common initial-access
vectors alongside credential phishing.

Covers:
  - Executable/script payloads by extension AND by file signature (magic
    bytes), since attackers rename .exe to .pdf.exe or strip extensions.
  - Macro-enabled Office documents (.docm/.xlsm/.pptm, or legacy .doc/.xls
    with an OLE vbaProject stream) — VBA macros are still the #1 initial
    payload dropper in phishing.
  - Nested/password-protected archives (.zip/.rar/.7z) used to evade
    attachment-type filters and sandboxes.
  - SHA256 hashing of every attachment so results can be checked against
    VirusTotal/MalwareBazaar later without needing to re-parse the email.

Dependencies: none beyond stdlib (zipfile, hashlib). For deep OLE macro
extraction beyond presence-detection, add `oletools` (`pip install oletools`)
and swap in `olevba.VBA_Parser` — flagged as a TODO below since it's a
heavier dependency you may not want in the hot path.
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from typing import Optional

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".jar", ".lnk", ".hta", ".reg",
}

MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}
LEGACY_OFFICE_EXTENSIONS = {".doc", ".xls", ".ppt"}  # may contain OLE VBA macros
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".iso"}

# File-signature (magic byte) map for the extensions that matter most —
# defends against attackers stripping/renaming the real extension.
MAGIC_BYTES = {
    b"MZ": "PE executable (.exe/.dll/.scr)",
    b"PK\x03\x04": "ZIP-based (docx/xlsx/pptx/zip/jar — inspect contents)",
    b"\xd0\xcf\x11\xe0": "Legacy OLE compound file (.doc/.xls/.ppt — may contain VBA)",
    b"Rar!\x1a\x07": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
}


@dataclass
class AttachmentFinding:
    filename: str
    sha256: str
    size_bytes: int
    signals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _detect_magic(content: bytes) -> Optional[str]:
    for magic, desc in MAGIC_BYTES.items():
        if content.startswith(magic):
            return desc
    return None


def _has_vba_project(zip_bytes: bytes) -> bool:
    """OOXML macro-enabled files (.docm etc.) are ZIPs containing
    'word/vbaProject.bin' or equivalent. Legacy OLE (.doc) macro detection
    needs oletools for a real parse — this ZIP check covers the modern
    .docm/.xlsm/.pptm case, which is the majority of what's mailed today."""
    try:
        with zipfile.ZipFile(BytesIO(zip_bytes)) as zf:
            return any("vbaProject.bin" in name for name in zf.namelist())
    except zipfile.BadZipFile:
        return False


def scan_attachment(filename: str, content: bytes) -> AttachmentFinding:
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    finding = AttachmentFinding(
        filename=filename,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )

    magic = _detect_magic(content)
    if magic:
        finding.notes.append(f"File signature: {magic}")

    # Extension/signature mismatch — attacker disguising payload type
    if magic == "PE executable (.exe/.dll/.scr)" and ext not in {".exe", ".dll", ".scr", ".com"}:
        finding.signals.append("attachment_executable")
        finding.notes.append(
            f"Filename claims '{ext or 'no extension'}' but file signature is a Windows PE executable."
        )
    elif ext in DANGEROUS_EXTENSIONS:
        finding.signals.append("attachment_executable")
        finding.notes.append(f"Extension '{ext}' is a known script/executable payload type.")

    if ext in MACRO_ENABLED_EXTENSIONS:
        finding.signals.append("attachment_macro_enabled")
        finding.notes.append(f"Extension '{ext}' is macro-enabled by definition.")
    elif ext in {".docx", ".xlsx", ".pptx"} and magic and magic.startswith("ZIP"):
        if _has_vba_project(content):
            finding.signals.append("attachment_macro_enabled")
            finding.notes.append(
                f"File is nominally '{ext}' (macro-free format) but contains a vbaProject.bin stream — "
                f"either mislabeled or deliberately evasive."
            )
    elif ext in LEGACY_OFFICE_EXTENSIONS:
        finding.notes.append(
            f"Legacy OLE format '{ext}' — macro presence not fully determined without oletools "
            f"(TODO: integrate olevba.VBA_Parser for definitive VBA extraction)."
        )

    if ext in ARCHIVE_EXTENSIONS:
        finding.signals.append("attachment_archive_nested")
        finding.notes.append(f"Archive attachment '{ext}' — contents not inspected without recursive unpacking.")
        if ext == ".zip":
            try:
                with zipfile.ZipFile(BytesIO(content)) as zf:
                    inner_dangerous = [n for n in zf.namelist()
                                        if any(n.lower().endswith(e) for e in DANGEROUS_EXTENSIONS)]
                    if inner_dangerous:
                        finding.signals.append("attachment_executable")
                        finding.notes.append(f"Archive contains dangerous file(s): {inner_dangerous[:5]}")
            except (zipfile.BadZipFile, RuntimeError):
                finding.notes.append("Archive could not be opened (corrupt or password-protected) — "
                                      "password-protected archives are themselves a common evasion technique.")

    return finding


def scan_all_attachments(attachments: list[tuple[str, bytes]]) -> list[AttachmentFinding]:
    """attachments: list of (filename, raw_bytes) tuples, as pulled from the
    parsed MIME message in Stage 1."""
    return [scan_attachment(name, content) for name, content in attachments]
