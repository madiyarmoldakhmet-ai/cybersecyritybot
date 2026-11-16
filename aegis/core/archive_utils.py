"""
Safe archive extraction helpers for uploaded ZIP archives.
Protects against path traversal (Zip Slip), symlink escapes, and decompression bombs.
"""

import stat
import zipfile
from pathlib import Path

MAX_ARCHIVE_FILES = 5000
MAX_EXTRACTED_BYTES = 150 * 1024 * 1024  # 150 MB uncompressed cap


def safe_extract_zip(zip_path: Path, extract_dir: Path) -> int:
    """Safely extract a ZIP archive into extract_dir. Returns number of extracted files."""
    dest_root = extract_dir.resolve()
    dest_root.mkdir(parents=True, exist_ok=True)

    total_bytes = 0
    extracted_files = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ARCHIVE_FILES:
            raise ValueError(f"ZIP archive contains too many entries (limit: {MAX_ARCHIVE_FILES}).")

        for info in infos:
            # Skip symlinks (Unix mode S_IFLNK = 0o120000 in upper 16 bits of external_attr)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                continue

            member_path = Path(info.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(f"Unsafe path in ZIP archive: {info.filename}")

            target_path = (dest_root / member_path).resolve()
            if target_path != dest_root and dest_root not in target_path.parents:
                raise ValueError(f"Unsafe path escape in ZIP archive: {info.filename}")

            if info.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            total_bytes += info.file_size
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError("Extracted archive exceeds the 150 MB size limit.")

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
            extracted_files += 1

    return extracted_files
