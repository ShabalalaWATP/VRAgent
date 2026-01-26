import asyncio
import logging
import os
import shlex
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, List, Optional

from backend.services.afl_telemetry_service import AflTelemetryRecorder, AflDirStats, get_afl_dir_stats
from backend.services.binary_fuzzer_service import QemuModeType, check_afl_installation, find_afl_tool

logger = logging.getLogger(__name__)


def _resolve_qemu_mode(qemu_mode: Optional[str]) -> Optional[QemuModeType]:
    if not qemu_mode:
        return None
    if isinstance(qemu_mode, QemuModeType):
        return qemu_mode
    try:
        return QemuModeType(str(qemu_mode))
    except ValueError:
        return None


def _parse_fuzzer_stats(stats_path: str) -> Dict[str, Any]:
    stats: Dict[str, Any] = {}
    if not os.path.isfile(stats_path):
        return stats

    try:
        with open(stats_path, "r", encoding="utf-8") as handle:
            for line in handle:
                if ":" not in line:
                    continue
                key, value = line.strip().split(":", 1)
                key = key.strip()
                value = value.strip()
                if key in ("bitmap_cvg", "stability"):
                    try:
                        stats[key] = float(value.replace("%", ""))
                    except ValueError:
                        continue
                else:
                    try:
                        stats[key] = int(float(value))
                    except ValueError:
                        stats[key] = value
    except Exception:
        return stats

    mapping = {
        "execs_done": "execs_done",
        "execs_per_sec": "execs_per_sec",
        "paths_total": "paths_total",
        "paths_found": "paths_found",
        "unique_crashes": "unique_crashes",
        "unique_hangs": "unique_hangs",
        "last_path": "last_path_time",
        "last_crash": "last_crash_time",
        "cycles_done": "cycle_done",
        "pending_total": "pending_total",
        "pending_favs": "pending_favs",
        "bitmap_cvg": "map_coverage",
        "stability": "stability",
    }
    normalized: Dict[str, Any] = {}
    for key, target in mapping.items():
        if key in stats:
            normalized[target] = stats[key]
    return normalized


def _aggregate_dir_stats(stats_list: List[AflDirStats]) -> AflDirStats:
    aggregate = AflDirStats()
    for stats in stats_list:
        aggregate.count += stats.count
        aggregate.total_bytes += stats.total_bytes
        if stats.newest_mtime is not None:
            if aggregate.newest_mtime is None or stats.newest_mtime > aggregate.newest_mtime:
                aggregate.newest_mtime = stats.newest_mtime
    return aggregate


def _aggregate_stats(stats_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    aggregate: Dict[str, Any] = {}
    sum_keys = {"execs_done", "execs_per_sec", "pending_total", "pending_favs"}
    max_keys = {"paths_total", "paths_found", "cycle_done", "map_coverage", "last_path_time", "last_crash_time"}
    avg_keys = {"stability"}
    counts: Dict[str, int] = {}

    for stats in stats_list:
        for key, value in stats.items():
            if not isinstance(value, (int, float)):
                continue
            if key in sum_keys:
                aggregate[key] = aggregate.get(key, 0) + value
            elif key in max_keys:
                aggregate[key] = max(aggregate.get(key, value), value)
            elif key in avg_keys:
                aggregate[key] = aggregate.get(key, 0) + value
                counts[key] = counts.get(key, 0) + 1

    for key in avg_keys:
        if key in aggregate:
            aggregate[key] = aggregate[key] / max(1, counts.get(key, 1))

    return aggregate


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


@dataclass
class AflClusterInstance:
    name: str
    role: str
    process: Optional[asyncio.subprocess.Process] = None
    start_time: Optional[float] = None
    exit_code: Optional[int] = None
    last_stats: Dict[str, Any] = field(default_factory=dict)
    last_error: Optional[str] = None

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.returncode is None


class AflClusterManager:
    def __init__(
        self,
        cluster_id: str,
        target_path: str,
        target_args: str,
        input_dir: str,
        output_dir: str,
        timeout_ms: int,
        memory_limit_mb: int,
        use_qemu: bool,
        qemu_mode: Optional[str],
        dictionary_path: Optional[str],
        env_vars: Optional[Dict[str, str]],
        extra_afl_flags: Optional[List[str]],
        persistent_address: Optional[str],
        persistent_count: int,
        persistent_hook: Optional[str],
        enable_compcov: bool,
        enable_instrim: bool,
        instance_count: int,
        master_name: str,
        slave_prefix: str,
        telemetry_dir: Optional[str],
        telemetry_interval_sec: float,
    ):
        self.cluster_id = cluster_id
        self.target_path = target_path
        self.target_args = target_args
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.timeout_ms = timeout_ms
        self.memory_limit_mb = memory_limit_mb
        self.use_qemu = use_qemu
        self.qemu_mode = _resolve_qemu_mode(qemu_mode)
        self.dictionary_path = dictionary_path
        self.env_vars = env_vars or {}
        self.extra_afl_flags = extra_afl_flags or []
        self.persistent_address = persistent_address
        self.persistent_count = persistent_count
        self.persistent_hook = persistent_hook
        self.enable_compcov = enable_compcov
        self.enable_instrim = enable_instrim
        self.instance_count = max(1, instance_count)
        self.master_name = master_name
        self.slave_prefix = slave_prefix
        self.telemetry_dir = telemetry_dir or os.path.join(self.output_dir, "telemetry")
        self.telemetry_interval_sec = max(0.5, telemetry_interval_sec)
        self._running = False
        self._stop_requested = False
        self._start_time: Optional[float] = None
        self._last_status: Dict[str, Any] = {}
        self._last_telemetry_ts = 0.0

        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.input_dir, exist_ok=True)

        instance_names = [self.master_name]
        for idx in range(1, self.instance_count):
            instance_names.append(f"{self.slave_prefix}{idx}")
        self.instances = [
            AflClusterInstance(name=name, role="master" if i == 0 else "slave")
            for i, name in enumerate(instance_names)
        ]

        metadata = {
            "cluster_id": self.cluster_id,
            "target_path": self.target_path,
            "target_args": self.target_args,
            "input_dir": self.input_dir,
            "output_dir": self.output_dir,
            "timeout_ms": self.timeout_ms,
            "memory_limit_mb": self.memory_limit_mb,
            "use_qemu": self.use_qemu,
            "qemu_mode": self.qemu_mode.value if self.qemu_mode else None,
            "dictionary_path": self.dictionary_path,
            "extra_afl_flags": self.extra_afl_flags,
            "instance_names": [inst.name for inst in self.instances],
        }
        try:
            self.telemetry = AflTelemetryRecorder(self.telemetry_dir, self.cluster_id, metadata)
        except Exception as exc:
            logger.warning(f"Failed to initialize cluster telemetry: {exc}")
            self.telemetry = None

    def _build_command(self, instance: AflClusterInstance) -> List[str]:
        afl_fuzz = find_afl_tool("afl-fuzz") or "afl-fuzz"
        cmd = [
            afl_fuzz,
            "-i",
            self.input_dir,
            "-o",
            self.output_dir,
            "-t",
            str(self.timeout_ms),
            "-m",
            str(self.memory_limit_mb),
        ]

        if instance.role == "master":
            cmd.extend(["-M", instance.name])
        else:
            cmd.extend(["-S", instance.name])

        if self.use_qemu:
            cmd.append("-Q")

        if self.dictionary_path and os.path.isfile(self.dictionary_path):
            cmd.extend(["-x", self.dictionary_path])

        if self.extra_afl_flags:
            cmd.extend(self.extra_afl_flags)

        cmd.append("--")
        cmd.append(self.target_path)
        if self.target_args:
            cmd.extend(shlex.split(self.target_args, posix=os.name != "nt"))
        return cmd

    def _build_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        env["AFL_NO_UI"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"

        if self.use_qemu and self.qemu_mode == QemuModeType.PERSISTENT and self.persistent_address:
            env["AFL_QEMU_PERSISTENT_ADDR"] = self.persistent_address
            env["AFL_QEMU_PERSISTENT_CNT"] = str(self.persistent_count)
            if self.persistent_hook:
                env["AFL_QEMU_PERSISTENT_HOOK"] = self.persistent_hook

        if self.enable_compcov or (self.use_qemu and self.qemu_mode == QemuModeType.COMPCOV):
            env["AFL_COMPCOV_LEVEL"] = "2"

        if self.enable_instrim or (self.use_qemu and self.qemu_mode == QemuModeType.INSTRIM):
            env["AFL_INST_RATIO"] = "50"

        if self.env_vars:
            env.update(self.env_vars)

        return env

    def get_status(self) -> Dict[str, Any]:
        return self._last_status or {
            "cluster_id": self.cluster_id,
            "running": self._running,
            "instances": [],
            "runtime_seconds": 0,
            "telemetry_dir": self.telemetry_dir,
        }

    async def stop(self):
        self._stop_requested = True
        for instance in self.instances:
            proc = instance.process
            if proc and proc.returncode is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    continue
        for instance in self.instances:
            proc = instance.process
            if proc and proc.returncode is None:
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()

    async def start(self) -> AsyncGenerator[Dict[str, Any], None]:
        availability = check_afl_installation()
        if not availability.get("installed"):
            yield {
                "type": "error",
                "error": "AFL++ not installed.",
            }
            return

        env = self._build_env()
        self._running = True
        self._start_time = time.time()

        for instance in self.instances:
            cmd = self._build_command(instance)
            logger.info(f"Starting AFL++ {instance.role}: {' '.join(cmd)}")
            try:
                instance.process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
                instance.start_time = time.time()
            except Exception as exc:
                instance.last_error = str(exc)
                self._running = False
                yield {
                    "type": "error",
                    "error": f"Failed to start instance {instance.name}: {exc}",
                    "cluster_id": self.cluster_id,
                }
                await self.stop()
                return

        yield {
            "type": "cluster_start",
            "cluster_id": self.cluster_id,
            "target": self.target_path,
            "output_dir": self.output_dir,
            "telemetry_dir": self.telemetry_dir,
            "instances": [
                {
                    "name": inst.name,
                    "role": inst.role,
                    "command": " ".join(self._build_command(inst)),
                }
                for inst in self.instances
            ],
        }

        end_status = "completed"
        end_error = None

        try:
            while self._running:
                instance_stats = []
                queue_stats_list = []
                crash_stats_list = []
                hang_stats_list = []
                instance_payload = []

                for instance in self.instances:
                    stats_path = os.path.join(self.output_dir, instance.name, "fuzzer_stats")
                    queue_dir = os.path.join(self.output_dir, instance.name, "queue")
                    crashes_dir = os.path.join(self.output_dir, instance.name, "crashes")
                    hangs_dir = os.path.join(self.output_dir, instance.name, "hangs")

                    stats = _parse_fuzzer_stats(stats_path)
                    instance.last_stats = stats
                    instance_stats.append(stats)

                    queue_stats_list.append(get_afl_dir_stats(queue_dir))
                    crash_stats_list.append(get_afl_dir_stats(crashes_dir, skip_names={"README.txt"}))
                    hang_stats_list.append(get_afl_dir_stats(hangs_dir, skip_names={"README.txt"}))

                    if instance.process and instance.process.returncode is not None and instance.exit_code is None:
                        instance.exit_code = instance.process.returncode
                        if instance.role == "master":
                            end_status = "error"
                            end_error = f"Master instance exited with code {instance.exit_code}"
                            self._running = False

                    instance_payload.append({
                        "name": instance.name,
                        "role": instance.role,
                        "running": instance.running,
                        "exit_code": instance.exit_code,
                        "stats": stats,
                    })

                aggregated_stats = _aggregate_stats(instance_stats)
                aggregate_queue = _aggregate_dir_stats(queue_stats_list)
                aggregate_crashes = _aggregate_dir_stats(crash_stats_list)
                aggregate_hangs = _aggregate_dir_stats(hang_stats_list)

                aggregated_stats["unique_crashes"] = aggregate_crashes.count
                aggregated_stats["unique_hangs"] = aggregate_hangs.count

                status = {
                    "cluster_id": self.cluster_id,
                    "running": self._running,
                    "target": self.target_path,
                    "output_dir": self.output_dir,
                    "telemetry_dir": self.telemetry_dir,
                    "runtime_seconds": time.time() - self._start_time if self._start_time else 0,
                    "instances": instance_payload,
                    "stats": aggregated_stats,
                    "queue": aggregate_queue.to_dict(),
                    "crashes": aggregate_crashes.to_dict(),
                    "hangs": aggregate_hangs.to_dict(),
                }
                self._last_status = status

                if self.telemetry:
                    now = time.time()
                    if now - self._last_telemetry_ts >= self.telemetry_interval_sec:
                        try:
                            self.telemetry.record_sample(
                                stats=aggregated_stats,
                                queue=aggregate_queue,
                                crashes=aggregate_crashes,
                                hangs=aggregate_hangs,
                                runtime_seconds=time.time() - self._start_time,
                            )
                        except Exception as exc:
                            logger.debug(f"Cluster telemetry sample failed: {exc}")
                        self._last_telemetry_ts = now

                yield {
                    "type": "status",
                    **status,
                }

                if self._stop_requested:
                    end_status = "stopped"
                    break

                await asyncio.sleep(2)

        except Exception as exc:
            logger.exception(f"AFL++ cluster error: {exc}")
            end_status = "error"
            end_error = str(exc)
            yield {
                "type": "error",
                "error": str(exc),
                "cluster_id": self.cluster_id,
            }
        finally:
            await self.stop()
            self._running = False
            if self.telemetry and self._start_time:
                try:
                    self.telemetry.finalize(
                        status=end_status,
                        runtime_seconds=time.time() - self._start_time,
                        final_stats=self._last_status.get("stats"),
                        error=end_error,
                    )
                except Exception as exc:
                    logger.debug(f"Cluster telemetry finalize failed: {exc}")

            yield {
                "type": "cluster_end",
                "cluster_id": self.cluster_id,
                "status": end_status,
                "error": end_error,
                "runtime_seconds": time.time() - self._start_time if self._start_time else 0,
                "telemetry_dir": self.telemetry_dir,
            }


_active_afl_clusters: Dict[str, AflClusterManager] = {}


async def start_afl_cluster(
    target_path: str,
    target_args: str = "@@",
    input_dir: str = "/fuzzing/seeds",
    output_dir: str = "/fuzzing/output",
    timeout_ms: int = 5000,
    memory_limit_mb: int = 256,
    use_qemu: bool = True,
    cluster_id: Optional[str] = None,
    dictionary: Optional[List[str]] = None,
    dictionary_path: Optional[str] = None,
    env_vars: Optional[Dict[str, str]] = None,
    extra_afl_flags: Optional[List[str]] = None,
    qemu_mode: Optional[str] = None,
    persistent_address: Optional[str] = None,
    persistent_count: int = 10000,
    persistent_hook: Optional[str] = None,
    enable_compcov: bool = False,
    enable_instrim: bool = False,
    instance_count: int = 2,
    master_name: str = "master",
    slave_prefix: str = "slave",
    telemetry_dir: Optional[str] = None,
    telemetry_interval_sec: float = 2.0,
) -> AsyncGenerator[Dict[str, Any], None]:
    if not os.path.isfile(target_path):
        yield {"type": "error", "error": f"Target not found: {target_path}"}
        return

    resolved_id = cluster_id or str(uuid.uuid4())
    final_output_dir = os.path.join(output_dir, resolved_id)
    os.makedirs(final_output_dir, exist_ok=True)

    if dictionary and not dictionary_path:
        dict_dir = os.path.join(final_output_dir, "dictionaries")
        os.makedirs(dict_dir, exist_ok=True)
        dict_path = os.path.join(dict_dir, "afl_dictionary.txt")
        try:
            with open(dict_path, "w", encoding="utf-8") as handle:
                for i, entry in enumerate(dictionary):
                    if entry is None:
                        continue
                    value = entry if isinstance(entry, bytes) else str(entry).encode("utf-8", errors="replace")
                    escaped = _escape_afl_dictionary_bytes(value)
                    handle.write(f"key{i}=\"{escaped}\"\n")
            dictionary_path = dict_path
        except Exception:
            dictionary_path = None

    manager = AflClusterManager(
        cluster_id=resolved_id,
        target_path=target_path,
        target_args=target_args,
        input_dir=input_dir,
        output_dir=final_output_dir,
        timeout_ms=timeout_ms,
        memory_limit_mb=memory_limit_mb,
        use_qemu=use_qemu,
        qemu_mode=qemu_mode,
        dictionary_path=dictionary_path,
        env_vars=env_vars,
        extra_afl_flags=extra_afl_flags,
        persistent_address=persistent_address,
        persistent_count=persistent_count,
        persistent_hook=persistent_hook,
        enable_compcov=enable_compcov,
        enable_instrim=enable_instrim,
        instance_count=instance_count,
        master_name=master_name,
        slave_prefix=slave_prefix,
        telemetry_dir=telemetry_dir,
        telemetry_interval_sec=telemetry_interval_sec,
    )

    _active_afl_clusters[resolved_id] = manager
    try:
        async for event in manager.start():
            yield event
    finally:
        _active_afl_clusters.pop(resolved_id, None)


def stop_afl_cluster(cluster_id: str) -> Dict[str, Any]:
    manager = _active_afl_clusters.get(cluster_id)
    if not manager:
        return {"success": False, "error": "Cluster not found"}
    asyncio.create_task(manager.stop())
    return {"success": True, "message": f"AFL++ cluster {cluster_id} stopping"}


def get_afl_cluster_status(cluster_id: str) -> Optional[Dict[str, Any]]:
    manager = _active_afl_clusters.get(cluster_id)
    if not manager:
        return None
    return manager.get_status()
