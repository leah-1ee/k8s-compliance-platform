import sys
from pathlib import Path


# 테스트 경로 등록
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))
