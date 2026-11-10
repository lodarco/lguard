"""File type by content (magic bytes), entropy, and the fake-media heuristics.

Extensions lie; the first bytes rarely do. Everything here works on a small
head sample read from an already-open descriptor.
"""
from __future__ import annotations

import math
import os
import re

HEAD = 64 * 1024

VIDEO_EXT = {"mkv", "mp4", "m4v", "avi", "mov", "wmv", "mpg", "mpeg", "ts", "m2ts",
             "mts", "webm", "flv", "vob", "3gp", "ogv", "divx", "xvid", "asf"}
AUDIO_EXT = {"mp3", "flac", "ogg", "opus", "m4a", "aac", "wav", "wma", "ac3", "dts"}
IMAGE_EXT = {"jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "heic"}
EXEC_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "msi", "msp", "lnk", "ps1",
            "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "cpl", "dll",
            "reg", "sh", "run", "appimage", "apk", "deb", "rpm", "elf", "bin", "url"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "xz", "bz2", "tar", "cab", "zst",
               "iso", "img", "dmg"}
OFFICE_ZIP_EXT = {"docx", "xlsx", "pptx", "odt", "ods", "odp", "docm", "xlsm", "pptm", "epub"}
OFFICE_OLE_EXT = {"doc", "xls", "ppt", "msg"}
TEXT_EXT = {"txt", "csv", "md", "json", "xml", "html", "htm", "srt", "sub", "ass",
            "nfo", "log", "ini", "yml", "yaml", "toml", "sql", "py", "php"}
SCRIPT_EXT = {"sh", "py", "pl", "php", "js", "ps1", "vbs", "bat", "cmd", "rb", "lua"}

# Media formats whose header we can positively identify.
_MAGIC = [
    ("elf", 0, b"\x7fELF"),
    ("pe", 0, b"MZ"),
    ("zip", 0, b"PK\x03\x04"),
    ("zip", 0, b"PK\x05\x06"),
    ("rar", 0, b"Rar!\x1a\x07"),
    ("7z", 0, b"7z\xbc\xaf\x27\x1c"),
    ("gzip", 0, b"\x1f\x8b"),
    ("xz", 0, b"\xfd7zXZ\x00"),
    ("bzip2", 0, b"BZh"),
    ("zstd", 0, b"\x28\xb5\x2f\xfd"),
    ("ole", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("lnk", 0, b"L\x00\x00\x00\x01\x14\x02\x00"),
    ("pdf", 0, b"%PDF"),
    ("jpeg", 0, b"\xff\xd8\xff"),
    ("png", 0, b"\x89PNG\r\n\x1a\n"),
    ("gif", 0, b"GIF8"),
    ("ebml", 0, b"\x1a\x45\xdf\xa3"),          # mkv / webm
    ("asf", 0, b"\x30\x26\xb2\x75\x8e\x66\xcf\x11"),  # wmv / wma
    ("flv", 0, b"FLV"),
    ("mpeg-ps", 0, b"\x00\x00\x01\xba"),
    ("id3", 0, b"ID3"),
    ("flac", 0, b"fLaC"),
    ("ogg", 0, b"OggS"),
    ("shebang", 0, b"#!"),
    ("sqlite", 0, b"SQLite format 3\x00"),
    ("psd", 0, b"8BPS"),
    ("tiff", 0, b"II*\x00"),                   # also most camera RAW formats
    ("tiff", 0, b"MM\x00*"),
    ("bmp", 0, b"BM"),
    ("rtf", 0, b"{\\rtf"),
    ("kdbx", 0, b"\x03\xd9\xa2\x9a"),
    ("dwg", 0, b"AC10"),
    ("class", 0, b"\xca\xfe\xba\xbe"),
    ("macho", 0, b"\xcf\xfa\xed\xfe"),
    ("macho", 0, b"\xce\xfa\xed\xfe"),
    ("onenote", 0, b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d"),
    ("tar", 257, b"ustar"),
]

EXECUTABLE_KINDS = {"elf", "pe", "lnk", "shebang", "macho", "class"}
ARCHIVE_KINDS = {"zip", "rar", "7z", "gzip", "xz", "bzip2", "zstd", "iso", "tar"}
VIDEO_KINDS = {"ebml", "mp4", "avi", "asf", "flv", "mpeg-ps", "mpeg-ts"}
# Positively identified media: nothing in the middle of these for the engine
# to unpack, so very big ones are scanned head and tail only.
MEDIA_KINDS = VIDEO_KINDS | {"wav", "flac", "ogg", "id3", "mpeg-audio"}
# Extensions that are a program whatever the content looks like.
STRONG_EXEC_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "msi", "msp", "lnk", "ps1", "vbs", "vbe",
                   "js", "jse", "wsf", "wsh", "hta", "jar", "cpl", "dll"}
# Documents that can carry scripts or exploits (re-checked with new signatures).
ACTIVE_DOC_EXT = {"html", "htm", "mht", "svg", "rtf", "eml", "msg", "one", "chm", "desktop", "xll",
                  "xlam", "ppam", "dotm", "xltm", "iqy", "slk", "wasm", "class", "swf"}


def is_program(magic: bytes) -> bool:
    """Cheap test on the first bytes: is this something that can run?"""
    return magic[:4] == b"\x7fELF" or magic[:2] in (b"MZ", b"#!") or \
        magic[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")


def kind(head: bytes) -> str:
    for name, off, sig in _MAGIC:
        if head[off:off + len(sig)] == sig:
            return name
    if len(head) >= 12 and head[4:8] in (b"ftyp", b"moov", b"mdat", b"free", b"wide", b"skip"):
        return "mp4"
    if head[:4] == b"RIFF" and len(head) >= 12:
        return {b"AVI ": "avi", b"WAVE": "wav", b"WEBP": "webp"}.get(head[8:12], "riff")
    if len(head) > 376 and head[0] == 0x47 and head[188] == 0x47 and head[376] == 0x47:
        return "mpeg-ts"
    if len(head) >= 2 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0:
        return "mpeg-audio"
    if is_text(head):
        return "text"
    return "unknown"


def is_iso(fd: int) -> bool:
    try:
        return os.pread(fd, 5, 0x8001) == b"CD001"
    except OSError:
        return False


def is_text(head: bytes) -> bool:
    if not head:
        return True
    if b"\x00" in head[:8192]:
        return False
    try:
        head[:8192].decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        # cut in the middle of a multi-byte char at the end of the sample
        return e.start >= len(head[:8192]) - 3


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8). Encrypted/compressed ~ 7.9+."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def ext_of(path: str) -> str:
    name = os.path.basename(path).lower()
    return name.rsplit(".", 1)[1] if "." in name else ""


def is_risky(k: str, ext: str) -> bool:
    """Worth re-scanning when new signatures arrive, while the file is new.
    A file of unknown type counts too: nobody knows what it is."""
    return (k in EXECUTABLE_KINDS or k in ARCHIVE_KINDS or k in ("pdf", "ole", "zip", "rtf", "onenote", "unknown")
            or ext in EXEC_EXT or ext in SCRIPT_EXT or ext in OFFICE_ZIP_EXT
            or ext in OFFICE_OLE_EXT or ext in ARCHIVE_EXT or ext in ACTIVE_DOC_EXT)


_DOUBLE_EXT = re.compile(
    r"\.(mkv|mp4|m4v|avi|mov|wmv|mpg|mpeg|webm|flv|mp3|flac|pdf|jpe?g|png|docx?|xlsx?|txt|srt)"
    r"[\s._-]*\.(exe|scr|lnk|bat|cmd|com|pif|vbs|vbe|js|jse|msi|hta|wsf|ps1|jar|cpl)$",
    re.IGNORECASE,
)


def media_verdict(path: str, k: str, fd: int, mode: str = "media") -> tuple[str, str] | None:
    """Heuristics for category folders. Returns (level, name) or None.

    level "suspicious" = quarantine; "warning" = report only.

    In every category: a name that pretends (Movie.mp4.exe) and a "video"
    that is really a program, an archive or a document.
    Only in mode "media" (a film or music library, where a program has no
    business): programs are quarantined; installers, disk images and archives
    in disguise are reported. In mode "downloads" those are normal content
    and are simply scanned like every other file.
    """
    name = os.path.basename(path)
    ext = ext_of(path)
    if _DOUBLE_EXT.search(name):
        return "suspicious", "Lguard.Media.DoubleExtension"
    if ext in VIDEO_EXT and (k in EXECUTABLE_KINDS or k in ARCHIVE_KINDS or k in ("ole", "pdf")
                             or (k == "text" and ext != "ts")):      # .ts is also TypeScript
        return "suspicious", f"Lguard.Media.FakeVideo.{k}"
    if mode != "media":
        return None
    if k in EXECUTABLE_KINDS or ext in STRONG_EXEC_EXT:
        return "suspicious", f"Lguard.Media.Executable.{k if k in EXECUTABLE_KINDS else ext}"
    if ext in EXEC_EXT:
        return "warning", f"Lguard.Media.Program.{ext}"
    if ext in ("iso", "img") or (ext not in VIDEO_EXT and k in ("unknown", "text") and is_iso(fd)):
        return "warning", "Lguard.Media.DiskImage"
    if k == "zip" and ext not in ARCHIVE_EXT | OFFICE_ZIP_EXT:
        return "warning", "Lguard.Media.HiddenArchive"
    return None


# Expected content per extension for the ransomware detector. A file whose
# extension says "document" but whose bytes are random noise was most likely
# encrypted in place.
_EXPECT = {
    **{e: {"zip"} for e in OFFICE_ZIP_EXT | {"zip", "jar", "apk"}},
    **{e: {"ole", "zip"} for e in OFFICE_OLE_EXT},
    "pdf": {"pdf"}, "rtf": {"rtf"}, "psd": {"psd"}, "kdbx": {"kdbx"}, "dwg": {"dwg"}, "tar": {"tar"},
    "bmp": {"bmp"}, "tif": {"tiff"}, "tiff": {"tiff"}, "cr2": {"tiff"}, "nef": {"tiff"}, "arw": {"tiff"},
    "dng": {"tiff"}, "heic": {"mp4"}, "cr3": {"mp4"},
    "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "png": {"png"}, "gif": {"gif"},
    "webp": {"webp"},
    "mkv": {"ebml"}, "webm": {"ebml"},
    "mp4": {"mp4"}, "m4v": {"mp4"}, "mov": {"mp4"}, "m4a": {"mp4"},
    "avi": {"avi"}, "wav": {"wav"}, "flac": {"flac"}, "ogg": {"ogg"},
    "mp3": {"id3", "mpeg-audio"},
    "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"}, "xz": {"xz"},
    **{e: {"text"} for e in ("txt", "csv", "md", "json", "xml", "html", "srt", "py", "sql", "yml", "yaml")},
}


def looks_encrypted(path: str, head: bytes) -> bool:
    """True if the name promises a known format, the header does not match
    it, and the content is near-random.

    Ransomware either keeps the name (report.docx) or appends its own
    extension (report.docx.locked); both are caught. A name without any known
    extension never counts, so random-looking files of unknown type are left
    alone."""
    if len(head) < 4096:
        return False
    name = os.path.basename(path).lower()
    parts = name.split(".")
    expected = _EXPECT.get(parts[-1]) if len(parts) > 1 else None
    if expected is None and len(parts) > 2:
        expected = _EXPECT.get(parts[-2])      # report.docx.locked
    if not expected:
        return False
    if kind(head) in expected:
        return False
    # also when only the beginning was encrypted (fast, "intermittent" ransomware)
    return entropy(head) > 7.5 or entropy(head[:4096]) > 7.5


def promises_format(path: str) -> bool:
    """The name says this is a document, picture or other personal file."""
    parts = os.path.basename(path).lower().split(".")
    return len(parts) > 1 and parts[-1] in _EXPECT


# Formats whose content is compressed by nature: high entropy is normal there.
NATURALLY_DENSE = {"zip", "gzip", "xz", "bzip2", "zstd", "7z", "rar", "jpeg", "png", "gif", "webp",
                   "mp4", "ebml", "asf", "flv", "avi", "ogg", "flac", "id3", "mpeg-audio", "pdf",
                   "ole", "sqlite", "mpeg-ts", "mpeg-ps", "tiff", "psd", "kdbx", "wav", "class"}


def looks_random(head: bytes) -> bool:
    """Content that is near-random and not a format that is compressed by
    nature: what a file looks like after ransomware encrypted it."""
    if len(head) < 4096:
        return False
    if kind(head) in NATURALLY_DENSE:
        return False
    return entropy(head) > 7.5
