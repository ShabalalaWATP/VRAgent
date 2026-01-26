import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from backend.services.ai_fuzzer_service import analyze_binary, generate_smart_seeds
from backend.services.binary_fuzzer_service import SmartDictionaryExtractor


def _iso_utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


@dataclass
class AiArtifactsResult:
    artifacts_dir: str
    seeds_dir: str
    dictionary_path: Optional[str]
    seed_count: int
    dictionary_entries: int
    generation_method: str
    manifest_path: str
    warnings: List[str]


def _safe_seed_name(name: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    cleaned = cleaned.strip("._-")
    if not cleaned:
        cleaned = fallback
    return cleaned[:64]


def _normalize_dictionary_entries(
    entries: Sequence[Any],
    max_entries: int,
    max_entry_bytes: int = 256,
) -> List[bytes]:
    seen: set = set()
    normalized: List[bytes] = []
    for entry in entries:
        if entry is None:
            continue
        if isinstance(entry, bytes):
            data = entry
        else:
            data = str(entry).encode("utf-8", errors="replace")
        if not data:
            continue
        if len(data) > max_entry_bytes:
            data = data[:max_entry_bytes]
        if data in seen:
            continue
        seen.add(data)
        normalized.append(data)
        if len(normalized) >= max_entries:
            break
    return normalized


def _escape_afl_dictionary_bytes(data: bytes) -> str:
    escaped = []
    for b in data:
        if 32 <= b <= 126 and b not in (34, 92):
            escaped.append(chr(b))
        elif b == 34:
            escaped.append('\\"')
        elif b == 92:
            escaped.append('\\\\')
        else:
            escaped.append(f"\\x{b:02x}")
    return "".join(escaped)


def _write_afl_dictionary_file(entries: List[bytes], output_dir: str) -> Optional[str]:
    if not entries:
        return None
    os.makedirs(output_dir, exist_ok=True)
    dict_path = os.path.join(output_dir, "afl_dictionary.txt")
    try:
        with open(dict_path, "w", encoding="utf-8") as handle:
            for idx, entry in enumerate(entries):
                escaped = _escape_afl_dictionary_bytes(entry)
                handle.write(f"key{idx}=\"{escaped}\"\n")
    except Exception:
        return None
    return dict_path


def _copy_existing_seeds(
    source_dir: str,
    dest_dir: str,
    max_seed_bytes: int,
) -> Tuple[int, int]:
    copied = 0
    skipped = 0
    if not os.path.isdir(source_dir):
        return copied, skipped
    os.makedirs(dest_dir, exist_ok=True)
    for entry in os.scandir(source_dir):
        if not entry.is_file():
            continue
        try:
            st = entry.stat()
        except FileNotFoundError:
            continue
        if st.st_size > max_seed_bytes:
            skipped += 1
            continue
        dest_path = os.path.join(dest_dir, entry.name)
        try:
            shutil.copy2(entry.path, dest_path)
            copied += 1
        except Exception:
            skipped += 1
    return copied, skipped


async def prepare_ai_artifacts(
    target_path: str,
    input_dir: Optional[str],
    artifacts_dir: str,
    num_seeds: int = 10,
    include_existing_seeds: bool = True,
    generate_dictionary: bool = True,
    dictionary_max_entries: int = 1000,
    use_smart_dictionary: bool = True,
    max_existing_seed_bytes: int = 1024 * 1024,
    extra_dictionary_entries: Optional[Iterable[str]] = None,
) -> AiArtifactsResult:
    warnings: List[str] = []
    artifacts_dir = str(Path(artifacts_dir))
    seeds_dir = os.path.join(artifacts_dir, "seeds")
    os.makedirs(seeds_dir, exist_ok=True)

    copied = 0
    skipped = 0
    if include_existing_seeds and input_dir:
        copied, skipped = _copy_existing_seeds(input_dir, seeds_dir, max_existing_seed_bytes)
        if skipped:
            warnings.append(f"Skipped {skipped} existing seeds larger than {max_existing_seed_bytes} bytes.")

    binary_name = Path(target_path).name
    seed_result = await generate_smart_seeds(
        binary_path=target_path,
        binary_name=binary_name,
        num_seeds=num_seeds,
        existing_seeds=None,
    )

    written_seeds: List[Dict[str, Any]] = []
    for idx, seed in enumerate(seed_result.seeds):
        safe_name = _safe_seed_name(seed.name, f"ai_seed_{idx}")
        filename = f"{safe_name}.bin"
        path = os.path.join(seeds_dir, filename)
        suffix = 1
        while os.path.exists(path):
            path = os.path.join(seeds_dir, f"{safe_name}_{suffix}.bin")
            suffix += 1
        with open(path, "wb") as handle:
            handle.write(seed.content)
        written_seeds.append({
            "name": seed.name,
            "path": path,
            "size": len(seed.content),
            "source": "ai",
            "description": seed.description,
            "format_type": seed.format_type,
            "mutation_hints": seed.mutation_hints,
        })

    dictionary_entries: List[Any] = []
    if generate_dictionary:
        dictionary_entries.extend(seed_result.recommended_dictionary or [])
        if extra_dictionary_entries:
            dictionary_entries.extend(list(extra_dictionary_entries))

        if use_smart_dictionary:
            try:
                extractor = SmartDictionaryExtractor(target_path)
                dictionary_entries.extend([entry.value for entry in extractor.extract_all()])
            except Exception as e:
                warnings.append(f"Smart dictionary extraction failed: {e}")

        if not dictionary_entries:
            binary_info = analyze_binary(target_path)
            dictionary_entries.extend(binary_info.strings)

    dictionary_bytes = _normalize_dictionary_entries(dictionary_entries, dictionary_max_entries)
    dictionary_path = _write_afl_dictionary_file(dictionary_bytes, artifacts_dir) if generate_dictionary else None

    manifest = {
        "schema_version": 1,
        "generated_at": _iso_utc_now(),
        "target_path": target_path,
        "generation_method": seed_result.generation_method,
        "seed_dir": seeds_dir,
        "seed_count": len(written_seeds),
        "copied_seed_count": copied,
        "dictionary_path": dictionary_path,
        "dictionary_entries": len(dictionary_bytes),
        "warnings": warnings,
        "input_format_analysis": seed_result.input_format_analysis,
        "fuzzing_strategy": seed_result.fuzzing_strategy,
        "seeds": written_seeds,
    }

    manifest_path = os.path.join(artifacts_dir, "ai_artifacts.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=True)

    return AiArtifactsResult(
        artifacts_dir=artifacts_dir,
        seeds_dir=seeds_dir,
        dictionary_path=dictionary_path,
        seed_count=len(written_seeds),
        dictionary_entries=len(dictionary_bytes),
        generation_method=seed_result.generation_method,
        manifest_path=manifest_path,
        warnings=warnings,
    )
