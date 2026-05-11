import os
import sys
import tempfile
from pathlib import Path


# 테스트 경로 등록
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))
os.environ.setdefault(
    "SQLITE_PATH",
    str(Path(tempfile.gettempdir()) / f"compliance-ai-server-test-{os.getpid()}.sqlite3"),
)
os.environ.setdefault("ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("PUBLIC_BASE_URL", "https://console.example.test")
