from __future__ import annotations

import urllib.request
from pathlib import Path

import soundfile as sf
from kokoro_onnx import Kokoro


ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / ".models"
MODEL = MODELS / "kokoro-v1.0.int8.onnx"
VOICES = MODELS / "voices-v1.0.bin"
OUTPUT = ROOT / "public" / "audio" / "pandax-voiceover.wav"
BASE = "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0"


def download(url: str, destination: Path) -> None:
    if destination.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {destination.name}...")
    urllib.request.urlretrieve(url, destination)


download(f"{BASE}/{MODEL.name}", MODEL)
download(f"{BASE}/{VOICES.name}", VOICES)

paragraphs = [
    line.strip()
    for line in (ROOT / "scripts" / "narration.txt").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
kokoro = Kokoro(str(MODEL), str(VOICES))
samples, sample_rate = kokoro.create(
    " ".join(paragraphs),
    voice="af_heart",
    speed=1.24,
    lang="en-us",
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
sf.write(OUTPUT, samples, sample_rate, subtype="PCM_16")
print(f"Generated {OUTPUT}")
