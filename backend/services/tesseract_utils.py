import os
import shutil
from typing import Optional


WINDOWS_TESSERACT_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
]


def find_tesseract_cmd() -> Optional[str]:
    env_cmd = os.getenv("TESSERACT_CMD")
    if env_cmd and os.path.exists(env_cmd):
        return env_cmd

    cmd = shutil.which("tesseract")
    if cmd:
        return cmd

    for path in WINDOWS_TESSERACT_PATHS:
        if os.path.exists(path):
            return path

    return None


def configure_pytesseract() -> Optional[str]:
    try:
        import pytesseract
    except ImportError:
        return None

    cmd = find_tesseract_cmd()
    if cmd:
        pytesseract.pytesseract.tesseract_cmd = cmd
    return cmd
