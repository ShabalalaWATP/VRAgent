"""
Dependency extraction service for parsing dependency manifest files.

Supports:
- Python: requirements.txt, Pipfile, pyproject.toml
- JavaScript/Node: package.json, package-lock.json
- Java: pom.xml (Maven), build.gradle (Gradle)
- Go: go.mod, go.sum
- Ruby: Gemfile, Gemfile.lock
- Rust: Cargo.toml, Cargo.lock
- PHP: composer.json, composer.lock

Note: When both manifest and lock files exist, lock files are preferred
for precise versions. Deduplication is performed to avoid duplicates.
"""

import json
import re
from defusedxml import ElementTree as ET  # Use defusedxml to prevent XXE attacks
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from backend import models
from backend.core.logging import get_logger

logger = get_logger(__name__)


def _deduplicate_dependencies(deps: List[models.Dependency]) -> List[models.Dependency]:
    """
    Deduplicate dependencies, preferring lock file versions over manifest versions.
    
    When the same package appears from both manifest and lock file,
    keep the lock file version (more precise).
    """
    # Key: (ecosystem, name), Value: (dependency, is_from_lock)
    seen: Dict[Tuple[str, str], Tuple[models.Dependency, bool]] = {}
    
    lock_file_patterns = {'lock', '.lock', 'Gemfile.lock', 'Cargo.lock', 'go.sum'}
    
    for dep in deps:
        key = (dep.ecosystem, dep.name.lower())
        is_lock = any(pattern in (dep.manifest_path or '') for pattern in lock_file_patterns)
        
        if key not in seen:
            seen[key] = (dep, is_lock)
        else:
            existing_dep, existing_is_lock = seen[key]
            # Prefer lock file version, or version with actual value
            if is_lock and not existing_is_lock:
                seen[key] = (dep, is_lock)
            elif dep.version and not existing_dep.version:
                seen[key] = (dep, is_lock)
    
    result = [dep for dep, _ in seen.values()]
    logger.debug(f"Deduplicated {len(deps)} -> {len(result)} dependencies")
    return result


def parse_dependencies(project: models.Project, source_root: Path) -> List[models.Dependency]:
    """
    Parse all dependency manifest files in a project.
    
    Args:
        project: Project model
        source_root: Root path of the source code
        
    Returns:
        List of Dependency models (deduplicated)
    """
    deps: List[models.Dependency] = []
    
    # Python - requirements.txt
    for req in source_root.rglob("requirements.txt"):
        deps.extend(_parse_requirements_txt(project.id, req, source_root))
    
    # Python - Pipfile
    for pipfile in source_root.rglob("Pipfile"):
        deps.extend(_parse_pipfile(project.id, pipfile, source_root))
    
    # Python - pyproject.toml
    for pyproject in source_root.rglob("pyproject.toml"):
        deps.extend(_parse_pyproject_toml(project.id, pyproject, source_root))
    
    # JavaScript/Node - package.json
    for pkg_file in source_root.rglob("package.json"):
        # Skip node_modules
        if "node_modules" in str(pkg_file):
            continue
        deps.extend(_parse_package_json(project.id, pkg_file, source_root))
    
    # JavaScript/Node - package-lock.json (precise versions)
    for lock_file in source_root.rglob("package-lock.json"):
        if "node_modules" in str(lock_file):
            continue
        deps.extend(_parse_package_lock_json(project.id, lock_file, source_root))
    
    # Java - pom.xml (Maven)
    for pom in source_root.rglob("pom.xml"):
        deps.extend(_parse_pom_xml(project.id, pom, source_root))
    
    # Java - build.gradle (Gradle)
    for gradle in source_root.rglob("build.gradle"):
        deps.extend(_parse_build_gradle(project.id, gradle, source_root))
    
    # Java - build.gradle.kts (Kotlin DSL)
    for gradle in source_root.rglob("build.gradle.kts"):
        deps.extend(_parse_build_gradle(project.id, gradle, source_root))
    
    # Go - go.mod
    for gomod in source_root.rglob("go.mod"):
        deps.extend(_parse_go_mod(project.id, gomod, source_root))
    
    # Go - go.sum (precise versions with checksums)
    for gosum in source_root.rglob("go.sum"):
        deps.extend(_parse_go_sum(project.id, gosum, source_root))
    
    # Ruby - Gemfile
    for gemfile in source_root.rglob("Gemfile"):
        if gemfile.name == "Gemfile":  # Exact match, not Gemfile.lock
            deps.extend(_parse_gemfile(project.id, gemfile, source_root))
    
    # Ruby - Gemfile.lock (more precise versions)
    for gemlock in source_root.rglob("Gemfile.lock"):
        deps.extend(_parse_gemfile_lock(project.id, gemlock, source_root))
    
    # Rust - Cargo.toml
    for cargo in source_root.rglob("Cargo.toml"):
        deps.extend(_parse_cargo_toml(project.id, cargo, source_root))
    
    # Rust - Cargo.lock (precise versions)
    for cargolock in source_root.rglob("Cargo.lock"):
        deps.extend(_parse_cargo_lock(project.id, cargolock, source_root))
    
    # PHP - composer.json
    for composer in source_root.rglob("composer.json"):
        # Skip vendor directory
        if "vendor" in str(composer):
            continue
        deps.extend(_parse_composer_json(project.id, composer, source_root))
    
    # PHP - composer.lock (precise versions)
    for composerlock in source_root.rglob("composer.lock"):
        if "vendor" in str(composerlock):
            continue
        deps.extend(_parse_composer_lock(project.id, composerlock, source_root))
    
    # Deduplicate dependencies (prefer lock file versions)
    deps = _deduplicate_dependencies(deps)
    
    logger.info(f"Extracted {len(deps)} dependencies for project {project.id}")
    return deps


def _parse_requirements_txt(project_id: int, req_path: Path, source_root: Path) -> List[models.Dependency]:
    """Parse Python requirements.txt file."""
    deps = []
    try:
        content = req_path.read_text(encoding='utf-8', errors='ignore')
        for line in content.splitlines():
            line = line.strip()
            # Skip empty lines, comments, and -r includes
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Skip URLs and git references
            if "@" in line or "://" in line:
                continue
            
            # Parse version specifiers
            name = None
            version = None
            
            if "==" in line:
                name, version = line.split("==", 1)
            elif ">=" in line:
                name, version = line.split(">=", 1)
                version = f">={version}"
            elif "<=" in line:
                name, version = line.split("<=", 1)
                version = f"<={version}"
            elif "~=" in line:
                name, version = line.split("~=", 1)
                version = f"~={version}"
            else:
                # Remove extras like [dev]
                name = re.sub(r'\[.*?\]', '', line).strip()
            
            if name:
                deps.append(
                    models.Dependency(
                        project_id=project_id,
                        name=name.strip(),
                        version=version.strip() if version else None,
                        ecosystem="PyPI",
                        manifest_path=str(req_path.relative_to(source_root)),
                    )
                )
    except Exception as e:
        logger.warning(f"Error parsing {req_path}: {e}")
    
    return deps


def _parse_pipfile(project_id: int, pipfile_path: Path, source_root: Path) -> List[models.Dependency]:
    """Parse Python Pipfile."""
    deps = []
    try:
        content = pipfile_path.read_text(encoding='utf-8', errors='ignore')
        current_section = None
        
        for line in content.splitlines():
            line = line.strip()
            
            # Check for section headers
            if line == "[packages]" or line == "[dev-packages]":
                current_section = "packages"
                continue
            elif line.startswith("["):
                current_section = None
                continue
            
            if current_section == "packages" and "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip().strip('"')
                version = parts[1].strip().strip('"')
                
                if version == "*":
                    version = None
                
                deps.append(
                    models.Dependency(
                        project_id=project_id,
                        name=name,
                        version=version,
                        ecosystem="PyPI",
                        manifest_path=str(pipfile_path.relative_to(source_root)),
                    )
                )
    except Exception as e:
        logger.warning(f"Error parsing {pipfile_path}: {e}")
    
    return deps


def _parse_pyproject_toml(project_id: int, pyproject_path: Path, source_root: Path) -> List[models.Dependency]:
    """Parse Python pyproject.toml file."""
    deps = []
    try:
        content = pyproject_path.read_text(encoding='utf-8', errors='ignore')
        
        # Simple regex-based parsing for dependencies
        # Look for dependencies = [...] section
        dep_pattern = re.compile(r'dependencies\s*=\s*\[(.*?)\]', re.DOTALL)
        match = dep_pattern.search(content)
        
        if match:
            deps_section = match.group(1)
            # Extract quoted strings
            dep_strings = re.findall(r'"([^"]+)"', deps_section)
            
            for dep_str in dep_strings:
                # Parse PEP 508 dependency specifiers
                match = re.match(r'^([a-zA-Z0-9_-]+)(.*)$', dep_str)
                if match:
                    name = match.group(1)
                    version = match.group(2).strip() if match.group(2) else None
                    
                    deps.append(
                        models.Dependency(
                            project_id=project_id,
                            name=name,
                            version=version,
                            ecosystem="PyPI",
                            manifest_path=str(pyproject_path.relative_to(source_root)),
                        )
                    )
    except Exception as e:
        logger.warning(f"Error parsing {pyproject_path}: {e}")
    
    return deps


def _parse_package_json(project_id: int, pkg_path: Path, source_root: Path) -> List[models.Dependency]:
    """Parse JavaScript/Node package.json file."""
    deps = []
    try:
        data = json.loads(pkg_path.read_text(encoding='utf-8', errors='ignore') or "{}")
        
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append(
                    models.Dependency(
                        project_id=project_id,
                        name=name,
                        version=version,
                        ecosystem="npm",
                        manifest_path=str(pkg_path.relative_to(source_root)),
                    )
                )
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing {pkg_path}: {e}")
    except Exception as e:
        logger.warning(f"Error reading {pkg_path}: {e}")
    
    return deps


def _parse_package_lock_json(project_id: int, lock_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse JavaScript/Node package-lock.json for precise versions.
    
    Supports both lockfileVersion 2/3 (packages) and v1 (dependencies).
    """
    deps = []
    try:
        data = json.loads(lock_path.read_text(encoding='utf-8', errors='ignore') or "{}")
        lockfile_version = data.get("lockfileVersion", 1)
        
        if lockfile_version >= 2:
            # v2/v3 format: uses "packages" object
            packages = data.get("packages", {})
            for pkg_path_key, pkg_info in packages.items():
                # Skip the root package (empty key "")
                if not pkg_path_key:
                    continue
                # Extract name from path like "node_modules/lodash"
                name = pkg_path_key.split("node_modules/")[-1]
                # Handle scoped packages like "@types/node"
                if "/" in name and not name.startswith("@"):
                    # This might be a nested dep, use the last part
                    name = name.split("/")[-1]
                
                version = pkg_info.get("version")
                if name and version:
                    deps.append(
                        models.Dependency(
                            project_id=project_id,
                            name=name,
                            version=version,
                            ecosystem="npm",
                            manifest_path=str(lock_path.relative_to(source_root)),
                        )
                    )
        else:
            # v1 format: uses "dependencies" object (recursive)
            def extract_deps(dependencies: dict):
                for name, info in dependencies.items():
                    version = info.get("version")
                    if version:
                        deps.append(
                            models.Dependency(
                                project_id=project_id,
                                name=name,
                                version=version,
                                ecosystem="npm",
                                manifest_path=str(lock_path.relative_to(source_root)),
                            )
                        )
                    # Recurse into nested dependencies
                    if info.get("dependencies"):
                        extract_deps(info["dependencies"])
            
            extract_deps(data.get("dependencies", {}))
        
        logger.debug(f"Parsed {len(deps)} dependencies from {lock_path}")
        
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing {lock_path}: {e}")
    except Exception as e:
        logger.warning(f"Error reading {lock_path}: {e}")
    
    return deps


def _parse_pom_xml(project_id: int, pom_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse Java Maven pom.xml file.
    
    Extracts dependencies from <dependencies> and <dependencyManagement> sections.
    """
    deps = []
    
    # Maven namespace
    ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
    
    try:
        content = pom_path.read_text(encoding='utf-8', errors='ignore')
        
        # Remove default namespace for easier parsing
        content = re.sub(r'xmlns="[^"]+"', '', content, count=1)
        
        root = ET.fromstring(content)
        
        # Properties for version interpolation
        properties: Dict[str, str] = {}
        props_elem = root.find('.//properties')
        if props_elem is not None:
            for prop in props_elem:
                tag = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
                if prop.text:
                    properties[tag] = prop.text.strip()
        
        def resolve_property(value: Optional[str]) -> Optional[str]:
            """Resolve ${property} references."""
            if not value:
                return value
            match = re.match(r'\$\{(.+)\}', value)
            if match:
                prop_name = match.group(1)
                return properties.get(prop_name, value)
            return value
        
        # Find all dependency elements
        for dep_elem in root.findall('.//dependency'):
            group_id = dep_elem.findtext('groupId')
            artifact_id = dep_elem.findtext('artifactId')
            version = dep_elem.findtext('version')
            scope = dep_elem.findtext('scope', 'compile')
            
            if group_id and artifact_id:
                # Resolve version properties
                version = resolve_property(version)
                
                # Format as Maven coordinate
                name = f"{group_id}:{artifact_id}"
                
                deps.append(
                    models.Dependency(
                        project_id=project_id,
                        name=name,
                        version=version,
                        ecosystem="Maven",
                        manifest_path=str(pom_path.relative_to(source_root)),
                    )
                )
                
        logger.debug(f"Parsed {len(deps)} dependencies from {pom_path}")
        
    except ET.ParseError as e:
        logger.warning(f"XML parsing error in {pom_path}: {e}")
    except Exception as e:
        logger.warning(f"Error parsing {pom_path}: {e}")
    
    return deps


def _parse_build_gradle(project_id: int, gradle_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse Java Gradle build.gradle or build.gradle.kts file.
    
    Extracts dependencies from various dependency configurations.
    """
    deps = []
    
    try:
        content = gradle_path.read_text(encoding='utf-8', errors='ignore')
        
        # Common dependency configurations
        configurations = [
            'implementation', 'api', 'compile', 'compileOnly',
            'runtimeOnly', 'testImplementation', 'testCompile',
            'annotationProcessor', 'kapt',
        ]
        
        # Pattern for string notation: implementation 'group:artifact:version'
        # Also handles: implementation("group:artifact:version")
        string_pattern = re.compile(
            r'(?:' + '|'.join(configurations) + r')\s*[\(\s]["\']([^"\']+)["\']',
            re.MULTILINE
        )
        
        for match in string_pattern.finditer(content):
            dep_str = match.group(1)
            parts = dep_str.split(':')
            
            if len(parts) >= 2:
                group_id = parts[0]
                artifact_id = parts[1]
                version = parts[2] if len(parts) > 2 else None
                
                name = f"{group_id}:{artifact_id}"
                
                deps.append(
                    models.Dependency(
                        project_id=project_id,
                        name=name,
                        version=version,
                        ecosystem="Maven",  # Gradle uses Maven Central
                        manifest_path=str(gradle_path.relative_to(source_root)),
                    )
                )
        
        # Pattern for map notation: implementation group: 'x', name: 'y', version: 'z'
        map_pattern = re.compile(
            r"(?:" + "|".join(configurations) + r")\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"](?:,\s*version:\s*['\"]([^'\"]+)['\"])?",
            re.MULTILINE
        )
        
        for match in map_pattern.finditer(content):
            group_id = match.group(1)
            artifact_id = match.group(2)
            version = match.group(3)
            
            name = f"{group_id}:{artifact_id}"
            
            deps.append(
                models.Dependency(
                    project_id=project_id,
                    name=name,
                    version=version,
                    ecosystem="Maven",
                    manifest_path=str(gradle_path.relative_to(source_root)),
                )
            )
        
        logger.debug(f"Parsed {len(deps)} dependencies from {gradle_path}")
        
    except Exception as e:
        logger.warning(f"Error parsing {gradle_path}: {e}")
    
    return deps


def _parse_go_mod(project_id: int, gomod_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse Go go.mod file.
    
    Extracts direct and indirect dependencies with versions.
    """
    deps = []
    
    try:
        content = gomod_path.read_text(encoding='utf-8', errors='ignore')
        in_require_block = False
        
        for line in content.splitlines():
            line = line.strip()
            
            # Track require blocks
            if line.startswith("require ("):
                in_require_block = True
                continue
            elif line == ")" and in_require_block:
                in_require_block = False
                continue
            
            # Single-line require
            if line.startswith("require ") and "(" not in line:
                parts = line[8:].strip().split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    deps.append(
                        models.Dependency(
                            project_id=project_id,
                            name=name,
                            version=version,
                            ecosystem="Go",
                            manifest_path=str(gomod_path.relative_to(source_root)),
                        )
                    )
            
            # Dependencies inside require block
            elif in_require_block and line and not line.startswith("//"):
                # Remove // indirect comment
                line = re.sub(r'\s*//.*$', '', line).strip()
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    deps.append(
                        models.Dependency(
                            project_id=project_id,
                            name=name,
                            version=version,
                            ecosystem="Go",
                            manifest_path=str(gomod_path.relative_to(source_root)),
                        )
                    )
        
        logger.debug(f"Parsed {len(deps)} dependencies from {gomod_path}")
        
    except Exception as e:
        logger.warning(f"Error parsing {gomod_path}: {e}")
    
    return deps


def _parse_go_sum(project_id: int, gosum_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse Go go.sum file for precise versions with checksums.
    
    go.sum contains checksums for module dependencies, providing precise version info.
    Format: <module> <version>[/go.mod] <hash>
    """
    deps = []
    seen_modules: Set[Tuple[str, str]] = set()  # (name, version) to dedupe
    
    try:
        content = gosum_path.read_text(encoding='utf-8', errors='ignore')
        
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version_str = parts[1]
                
                # Remove /go.mod suffix if present
                version = version_str.replace("/go.mod", "")
                
                # Skip duplicate entries (go.sum has both module and go.mod entries)
                key = (name, version)
                if key in seen_modules:
                    continue
                seen_modules.add(key)
                
                deps.append(
                    models.Dependency(
                        project_id=project_id,
                        name=name,
                        version=version,
                        ecosystem="Go",
                        manifest_path=str(gosum_path.relative_to(source_root)),
                    )
                )
        
        logger.debug(f"Parsed {len(deps)} dependencies from {gosum_path}")
        
    except Exception as e:
        logger.warning(f"Error parsing {gosum_path}: {e}")
    
    return deps


def _parse_gemfile(project_id: int, gemfile_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse Ruby Gemfile.
    
    Extracts gem dependencies with optional version constraints.
    """
    deps = []
    
    try:
        content = gemfile_path.read_text(encoding='utf-8', errors='ignore')
        
        # Pattern for gem 'name' or gem "name" with optional version
        # gem 'rails', '~> 7.0'
        # gem "pg", ">= 1.0"
        # gem 'sidekiq'
        gem_pattern = re.compile(
            r'''gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?''',
            re.MULTILINE
        )
        
        for match in gem_pattern.finditer(content):
            name = match.group(1)
            version = match.group(2)  # May be None
            
            deps.append(
                models.Dependency(
                    project_id=project_id,
                    name=name,
                    version=version,
                    ecosystem="RubyGems",
                    manifest_path=str(gemfile_path.relative_to(source_root)),
                )
            )
        
        logger.debug(f"Parsed {len(deps)} dependencies from {gemfile_path}")
        
    except Exception as e:
        logger.warning(f"Error parsing {gemfile_path}: {e}")
    
    return deps


def _parse_gemfile_lock(project_id: int, lock_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse Ruby Gemfile.lock for precise versions.
    
    Extracts gems from the specs section with exact versions.
    """
    deps = []
    
    try:
        content = lock_path.read_text(encoding='utf-8', errors='ignore')
        in_specs = False
        
        for line in content.splitlines():
            # Track GEM/specs section
            if line.strip() == "GEM":
                continue
            elif line.strip() == "specs:":
                in_specs = True
                continue
            elif line and not line.startswith(" "):
                in_specs = False
                continue
            
            if in_specs:
                # Lines like "    rails (7.0.4)" (4 spaces = direct dep)
                match = re.match(r'^    ([a-zA-Z0-9_-]+)\s+\(([^)]+)\)$', line)
                if match:
                    name = match.group(1)
                    version = match.group(2)
                    
                    deps.append(
                        models.Dependency(
                            project_id=project_id,
                            name=name,
                            version=version,
                            ecosystem="RubyGems",
                            manifest_path=str(lock_path.relative_to(source_root)),
                        )
                    )
        
        logger.debug(f"Parsed {len(deps)} dependencies from {lock_path}")
        
    except Exception as e:
        logger.warning(f"Error parsing {lock_path}: {e}")
    
    return deps


def _parse_cargo_toml(project_id: int, cargo_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse Rust Cargo.toml file.
    
    Extracts dependencies from [dependencies], [dev-dependencies], [build-dependencies].
    """
    deps = []
    
    try:
        content = cargo_path.read_text(encoding='utf-8', errors='ignore')
        current_section = None
        dep_sections = {'[dependencies]', '[dev-dependencies]', '[build-dependencies]'}
        
        for line in content.splitlines():
            line_stripped = line.strip()
            
            # Check for section headers
            if line_stripped.startswith('['):
                if line_stripped in dep_sections:
                    current_section = "deps"
                elif line_stripped.startswith('[dependencies.') or \
                     line_stripped.startswith('[dev-dependencies.') or \
                     line_stripped.startswith('[build-dependencies.'):
                    # Inline table like [dependencies.serde]
                    # Extract package name
                    match = re.match(r'\[(?:dev-|build-)?dependencies\.([^\]]+)\]', line_stripped)
                    if match:
                        name = match.group(1)
                        # Version will be on subsequent lines, but add dep without version for now
                        deps.append(
                            models.Dependency(
                                project_id=project_id,
                                name=name,
                                version=None,
                                ecosystem="crates.io",
                                manifest_path=str(cargo_path.relative_to(source_root)),
                            )
                        )
                    current_section = None
                else:
                    current_section = None
                continue
            
            if current_section == "deps" and "=" in line_stripped:
                # Simple form: serde = "1.0"
                # Table form: serde = { version = "1.0", features = ["derive"] }
                parts = line_stripped.split("=", 1)
                name = parts[0].strip()
                value = parts[1].strip()
                
                version = None
                if value.startswith('"'):
                    # Simple string version
                    version = value.strip('"')
                elif value.startswith('{'):
                    # Table form - extract version
                    version_match = re.search(r'version\s*=\s*"([^"]+)"', value)
                    if version_match:
                        version = version_match.group(1)
                
                if name and not name.startswith('#'):
                    deps.append(
                        models.Dependency(
                            project_id=project_id,
                            name=name,
                            version=version,
                            ecosystem="crates.io",
                            manifest_path=str(cargo_path.relative_to(source_root)),
                        )
                    )
        
        logger.debug(f"Parsed {len(deps)} dependencies from {cargo_path}")
        
    except Exception as e:
        logger.warning(f"Error parsing {cargo_path}: {e}")
    
    return deps


def _parse_cargo_lock(project_id: int, lock_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse Rust Cargo.lock for precise versions.
    
    Extracts all packages with exact versions.
    """
    deps = []
    
    try:
        content = lock_path.read_text(encoding='utf-8', errors='ignore')
        current_package = {}
        
        for line in content.splitlines():
            line = line.strip()
            
            if line == "[[package]]":
                # Save previous package
                if current_package.get('name'):
                    deps.append(
                        models.Dependency(
                            project_id=project_id,
                            name=current_package['name'],
                            version=current_package.get('version'),
                            ecosystem="crates.io",
                            manifest_path=str(lock_path.relative_to(source_root)),
                        )
                    )
                current_package = {}
            elif line.startswith('name = '):
                current_package['name'] = line.split('=', 1)[1].strip().strip('"')
            elif line.startswith('version = '):
                current_package['version'] = line.split('=', 1)[1].strip().strip('"')
        
        # Don't forget last package
        if current_package.get('name'):
            deps.append(
                models.Dependency(
                    project_id=project_id,
                    name=current_package['name'],
                    version=current_package.get('version'),
                    ecosystem="crates.io",
                    manifest_path=str(lock_path.relative_to(source_root)),
                )
            )
        
        logger.debug(f"Parsed {len(deps)} dependencies from {lock_path}")
        
    except Exception as e:
        logger.warning(f"Error parsing {lock_path}: {e}")
    
    return deps


def _parse_composer_json(project_id: int, composer_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse PHP composer.json file.
    
    Extracts require and require-dev dependencies.
    """
    deps = []
    
    try:
        data = json.loads(composer_path.read_text(encoding='utf-8', errors='ignore') or "{}")
        
        for section in ("require", "require-dev"):
            for name, version in data.get(section, {}).items():
                # Skip PHP version constraints and extensions
                if name == "php" or name.startswith("ext-"):
                    continue
                    
                deps.append(
                    models.Dependency(
                        project_id=project_id,
                        name=name,
                        version=version,
                        ecosystem="Packagist",
                        manifest_path=str(composer_path.relative_to(source_root)),
                    )
                )
        
        logger.debug(f"Parsed {len(deps)} dependencies from {composer_path}")
        
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing {composer_path}: {e}")
    except Exception as e:
        logger.warning(f"Error reading {composer_path}: {e}")
    
    return deps


def _parse_composer_lock(project_id: int, lock_path: Path, source_root: Path) -> List[models.Dependency]:
    """
    Parse PHP composer.lock for precise versions.
    
    Extracts packages and packages-dev with exact versions.
    """
    deps = []
    
    try:
        data = json.loads(lock_path.read_text(encoding='utf-8', errors='ignore') or "{}")
        
        for section in ("packages", "packages-dev"):
            for package in data.get(section, []):
                name = package.get("name")
                version = package.get("version")
                
                if name:
                    # Remove 'v' prefix from version if present
                    if version and version.startswith('v'):
                        version = version[1:]
                    
                    deps.append(
                        models.Dependency(
                            project_id=project_id,
                            name=name,
                            version=version,
                            ecosystem="Packagist",
                            manifest_path=str(lock_path.relative_to(source_root)),
                        )
                    )
        
        logger.debug(f"Parsed {len(deps)} dependencies from {lock_path}")
        
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing {lock_path}: {e}")
    except Exception as e:
        logger.warning(f"Error reading {lock_path}: {e}")
    
    return deps

