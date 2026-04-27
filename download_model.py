from pathlib import Path
from huggingface_hub import snapshot_download

BASE_DIR = Path(__file__).resolve().parent
TARGET_DIR = BASE_DIR / "models" / "gte-small-onnx"

TARGET_DIR.parent.mkdir(parents=True, exist_ok=True)

snapshot_download(
    repo_id="Qdrant/gte-small-onnx",
    local_dir=str(TARGET_DIR),
    local_dir_use_symlinks=False
)

print(f"Model downloaded to: {TARGET_DIR}")
