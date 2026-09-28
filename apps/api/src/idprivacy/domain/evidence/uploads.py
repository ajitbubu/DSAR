"""Validation for staff-uploaded supporting evidence (threat model T-18; decision D-10)."""

from dataclasses import dataclass

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
# extension -> (declared MIME type, magic bytes prefix)
ALLOWED: dict[str, tuple[str, bytes]] = {
    "pdf": ("application/pdf", b"%PDF-"),
    "png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    "jpg": ("image/jpeg", b"\xff\xd8\xff"),
    "jpeg": ("image/jpeg", b"\xff\xd8\xff"),
}


class UploadRejected(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class ValidUpload:
    ext: str  # normalised: pdf | png | jpg
    media_type: str


def validate(filename: str, declared_type: str, data: bytes) -> ValidUpload:
    """Extension, declared MIME type and file signature must all agree."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadRejected(413, "file is too large")
    if not data:
        raise UploadRejected(422, "file is empty")
    name = filename.strip().lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if ext not in ALLOWED or name.count(".") > 1 and name.split(".")[-2] in {"exe", "js", "html"}:
        raise UploadRejected(415, "only PDF, PNG and JPEG files are accepted")
    mime, magic = ALLOWED[ext]
    if declared_type.split(";")[0].strip().lower() != mime:
        raise UploadRejected(415, "declared file type doesn't match the extension")
    if not data.startswith(magic):
        raise UploadRejected(415, "file contents don't match the extension")
    if ext in ("png", "jpg", "jpeg") and b"<script" in data[:4096].lower():
        raise UploadRejected(415, "file looks like a polyglot")
    return ValidUpload("jpg" if ext == "jpeg" else ext, mime)
