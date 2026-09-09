from __future__ import annotations

import urllib.request
from pathlib import Path

import soundfile as sf
from kokoro_onnx import Kokoro


ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / ".models"
MODEL = MODELS / "kokoro-v1.0.int8.onnx"
VOICES = MODELS / "voices-v1.0.bin"
OUTPUT = ROOT / "public" / "audio"
BASE = "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0"
NAMES = ("intro", "pipeline", "alert", "upgrade", "document", "outro")


def download(url: str, destination: Path) -> None:
    if destination.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {destination.name}...")
    urllib.request.urlretrieve(url, destination)


download(f"{BASE}/{MODEL.name}", MODEL)
download(f"{BASE}/{VOICES.name}", VOICES)

lines = [
    line.strip()
    for line in (ROOT / "scripts" / "narration.txt").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
if len(lines) != len(NAMES):
    raise ValueError(f"Expected {len(NAMES)} narration lines, found {len(lines)}")

kokoro = Kokoro(str(MODEL), str(VOICES))
OUTPUT.mkdir(parents=True, exist_ok=True)
for name, line in zip(NAMES, lines, strict=True):
    samples, sample_rate = kokoro.create(line, voice="af_heart", speed=1.2, lang="en-us")
    path = OUTPUT / f"{name}.wav"
    sf.write(path, samples, sample_rate, subtype="PCM_16")
    print(f"Generated {path}")
