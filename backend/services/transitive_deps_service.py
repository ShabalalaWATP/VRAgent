"""
Transitive Dependency Analysis Service

Analyzes full dependency trees to identify:
1. Transitive (indirect) dependencies with vulnerabilities
2. Dependency chains showing how vulnerable packages are reached
3. Impact analysis - which direct dependencies pull in vulnerable code

Supports:
- npm (package-lock.json) 
- Python (Pipfile.lock, poetry.lock)
- Go (go.sum)
- Ruby (Gemfile.lock)
- Rust (Cargo.lock)
- PHP (composer.lock)
- Java (Maven dependency:tree output, gradle dependencies)
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DependencyNode:
    """Represents a node in the dependency tree."""
    name: str
    version: Optional[str] = None
    ecosystem: str = ""
    is_direct: bool = False
    is_dev: bool = False
    # Parent dependencies that require this package
    required_by: List[str] = field(default_factory=list)
    # Child dependencies this package requires
    requires: List[str] = field(default_factory=list)
    # Depth in dependency tree (0 = direct)
    depth: int = 0
    # Full path from root
    dependency_path: List[str] = field(default_factory=list)


@dataclass
class TransitiveDependencyInfo:
    """Information about a transitive dependency chain."""
    vulnerable_package: str
    vulnerable_version: str
    vulnerability_id: str
    is_direct: bool
    depth: int
    # Chain from direct dep to vulnerable package
    dependency_chain: List[str]
    # Direct dependency that pulls this in
    root_dependency: str
    # All paths to this vulnerable package
    all_paths: List[List[str]] = field(default_factory=list)


@dataclass
class DependencyTree:
    """Complete dependency tree for a project."""
    ecosystem: str
    # All nodes keyed by "name@version"
    nodes: Dict[str, DependencyNode] = field(default_factory=dict)
    # Direct dependencies
    direct_deps: Set[str] = field(default_factory=set)
    # Dev dependencies
    dev_deps: Set[str] = field(default_factory=set)
    # Total count
    total_count: int = 0
    # Max depth
    max_depth: int = 0


def _normalize_package_key(name: str, version: Optional[str] = None) -> str:
    """Create a normalized key for a package."""
    if version:
        return f"{name.lower()}@{version}"
    return name.lower()


def parse_npm_lock_tree(lock_path: Path) -> DependencyTree:
    """
    Parse npm package-lock.json to build full dependency tree.
    
    Supports lockfileVersion 2 and 3 (packages format).
    """
    tree = DependencyTree(ecosystem="npm")
    
    try:
        data = json.loads(lock_path.read_text(encoding='utf-8', errors='ignore') or "{}")
        lockfile_version = data.get("lockfileVersion", 1)
        
        # Get direct dependencies from package.json reference
        direct_deps = set(data.get("dependencies", {}).keys())
        dev_deps_names = set()  # Would need package.json for this
        
        if lockfile_version >= 2:
            # v2/v3 format uses "packages" object
            packages = data.get("packages", {})
            
            # First pass: create all nodes
            for pkg_path, pkg_info in packages.items():
                if not pkg_path:  # Skip root
                    continue
                
                # Extract name from path like "node_modules/lodash" or nested
                parts = pkg_path.split("node_modules/")
                name = parts[-1] if parts else pkg_path
                version = pkg_info.get("version")
                
                if not name or name.startswith("."):
                    continue
                
                key = _normalize_package_key(name, version)
                is_direct = name in direct_deps
                depth = pkg_path.count("node_modules/") - 1
                
                node = DependencyNode(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    is_direct=is_direct,
                    is_dev=pkg_info.get("dev", False),
                    depth=max(0, depth),
                )
                
                # Get dependencies of this package
                for dep_name in pkg_info.get("dependencies", {}).keys():
                    node.requires.append(dep_name)
                
                tree.nodes[key] = node
                
                if is_direct:
                    tree.direct_deps.add(key)
                if node.is_dev:
                    tree.dev_deps.add(key)
                
                tree.max_depth = max(tree.max_depth, node.depth)
            
            # Second pass: build required_by relationships
            for key, node in tree.nodes.items():
                for req in node.requires:
                    # Find the actual resolved version
                    for other_key, other_node in tree.nodes.items():
                        if other_node.name == req:
                            other_node.required_by.append(node.name)
                            break
        
        else:
            # v1 format uses nested "dependencies"
            def process_deps(deps_obj: dict, parent: Optional[str] = None, depth: int = 0):
                for name, info in deps_obj.items():
                    version = info.get("version")
                    key = _normalize_package_key(name, version)
                    is_direct = depth == 0
                    
                    node = DependencyNode(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        is_direct=is_direct,
                        is_dev=info.get("dev", False),
                        depth=depth,
                    )
                    
                    if parent:
                        node.required_by.append(parent)
                    
                    # Get direct requires
                    if info.get("requires"):
                        node.requires = list(info["requires"].keys())
                    
                    tree.nodes[key] = node
                    
                    if is_direct:
                        tree.direct_deps.add(key)
                    
                    tree.max_depth = max(tree.max_depth, depth)
                    
                    # Process nested dependencies
                    if info.get("dependencies"):
                        process_deps(info["dependencies"], name, depth + 1)
            
            process_deps(data.get("dependencies", {}))
        
        tree.total_count = len(tree.nodes)
        logger.debug(f"Parsed npm lock: {tree.total_count} packages, max depth {tree.max_depth}")
        
    except Exception as e:
        logger.warning(f"Error parsing npm lock file {lock_path}: {e}")
    
    return tree


def parse_pipfile_lock_tree(lock_path: Path) -> DependencyTree:
    """
    Parse Pipfile.lock to build dependency tree.
    
    Note: Pipfile.lock doesn't store full tree, but we can identify direct vs transitive.
    """
    tree = DependencyTree(ecosystem="PyPI")
    
    try:
        data = json.loads(lock_path.read_text(encoding='utf-8', errors='ignore') or "{}")
        
        # Default section has production deps
        for name, info in data.get("default", {}).items():
            version = info.get("version", "").lstrip("=")
            key = _normalize_package_key(name, version)
            
            node = DependencyNode(
                name=name,
                version=version,
                ecosystem="PyPI",
                is_direct=True,  # Pipfile.lock only has resolved deps
                is_dev=False,
                depth=0,
            )
            
            tree.nodes[key] = node
            tree.direct_deps.add(key)
        
        # develop section has dev deps
        for name, info in data.get("develop", {}).items():
            version = info.get("version", "").lstrip("=")
            key = _normalize_package_key(name, version)
            
            node = DependencyNode(
                name=name,
                version=version,
                ecosystem="PyPI",
                is_direct=True,
                is_dev=True,
                depth=0,
            )
            
            tree.nodes[key] = node
            tree.dev_deps.add(key)
        
        tree.total_count = len(tree.nodes)
        
    except Exception as e:
        logger.warning(f"Error parsing Pipfile.lock {lock_path}: {e}")
    
    return tree


def parse_poetry_lock_tree(lock_path: Path) -> DependencyTree:
    """
    Parse poetry.lock to build dependency tree.
    
    Poetry lock files have explicit dependency information.
    """
    tree = DependencyTree(ecosystem="PyPI")
    
    try:
        content = lock_path.read_text(encoding='utf-8', errors='ignore')
        
        # Simple TOML-like parsing for [[package]] sections
        current_package = {}
        in_deps = False
        
        for line in content.splitlines():
            line = line.strip()
            
            if line == "[[package]]":
                # Save previous package
                if current_package.get("name"):
                    name = current_package["name"]
                    version = current_package.get("version")
                    key = _normalize_package_key(name, version)
                    
                    node = DependencyNode(
                        name=name,
                        version=version,
                        ecosystem="PyPI",
                        is_direct=current_package.get("category") != "dev",
                        is_dev=current_package.get("category") == "dev",
                        requires=current_package.get("deps", []),
                    )
                    
                    tree.nodes[key] = node
                    if node.is_direct:
                        tree.direct_deps.add(key)
                    else:
                        tree.dev_deps.add(key)
                
                current_package = {"deps": []}
                in_deps = False
                
            elif line.startswith("name = "):
                current_package["name"] = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                current_package["version"] = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("category = "):
                current_package["category"] = line.split("=", 1)[1].strip().strip('"')
            elif line == "[package.dependencies]":
                in_deps = True
            elif line.startswith("[") and in_deps:
                in_deps = False
            elif in_deps and "=" in line:
                dep_name = line.split("=")[0].strip()
                if dep_name and not dep_name.startswith("#"):
                    current_package["deps"].append(dep_name)
        
        # Don't forget last package
        if current_package.get("name"):
            name = current_package["name"]
            version = current_package.get("version")
            key = _normalize_package_key(name, version)
            
            node = DependencyNode(
                name=name,
                version=version,
                ecosystem="PyPI",
                is_direct=current_package.get("category") != "dev",
                is_dev=current_package.get("category") == "dev",
                requires=current_package.get("deps", []),
            )
            
            tree.nodes[key] = node
        
        # Build required_by relationships
        for key, node in tree.nodes.items():
            for req in node.requires:
                for other_key, other_node in tree.nodes.items():
                    if other_node.name.lower() == req.lower():
                        other_node.required_by.append(node.name)
                        break
        
        # Calculate depths
        _calculate_depths(tree)
        
        tree.total_count = len(tree.nodes)
        
    except Exception as e:
        logger.warning(f"Error parsing poetry.lock {lock_path}: {e}")
    
    return tree


def parse_cargo_lock_tree(lock_path: Path) -> DependencyTree:
    """
    Parse Cargo.lock to build Rust dependency tree.
    """
    tree = DependencyTree(ecosystem="crates.io")
    
    try:
        content = lock_path.read_text(encoding='utf-8', errors='ignore')
        current_package = {}
        in_deps = False
        
        for line in content.splitlines():
            line = line.strip()
            
            if line == "[[package]]":
                # Save previous package
                if current_package.get("name"):
                    name = current_package["name"]
                    version = current_package.get("version")
                    key = _normalize_package_key(name, version)
                    
                    node = DependencyNode(
                        name=name,
                        version=version,
                        ecosystem="crates.io",
                        requires=current_package.get("deps", []),
                    )
                    
                    tree.nodes[key] = node
                
                current_package = {"deps": []}
                in_deps = False
                
            elif line.startswith("name = "):
                current_package["name"] = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                current_package["version"] = line.split("=", 1)[1].strip().strip('"')
            elif line == "dependencies = [":
                in_deps = True
            elif line == "]" and in_deps:
                in_deps = False
            elif in_deps:
                # Dependency format: "package_name version"
                dep_match = re.match(r'"([^"]+)', line)
                if dep_match:
                    dep_str = dep_match.group(1)
                    dep_name = dep_str.split()[0]
                    current_package["deps"].append(dep_name)
        
        # Don't forget last package
        if current_package.get("name"):
            name = current_package["name"]
            version = current_package.get("version")
            key = _normalize_package_key(name, version)
            
            node = DependencyNode(
                name=name,
                version=version,
                ecosystem="crates.io",
                requires=current_package.get("deps", []),
            )
            
            tree.nodes[key] = node
        
        # Build required_by and identify direct deps
        _build_relationships_and_depths(tree)
        
        tree.total_count = len(tree.nodes)
        
    except Exception as e:
        logger.warning(f"Error parsing Cargo.lock {lock_path}: {e}")
    
    return tree


def parse_gemfile_lock_tree(lock_path: Path) -> DependencyTree:
    """
    Parse Gemfile.lock to build Ruby dependency tree.
    """
    tree = DependencyTree(ecosystem="RubyGems")
    
    try:
        content = lock_path.read_text(encoding='utf-8', errors='ignore')
        in_specs = False
        current_gem = None
        
        for line in content.splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            elif line and not line.startswith(" "):
                in_specs = False
                continue
            
            if in_specs:
                # Direct dependency: "    gem_name (version)"
                direct_match = re.match(r'^    ([a-zA-Z0-9_-]+)\s+\(([^)]+)\)$', line)
                if direct_match:
                    name = direct_match.group(1)
                    version = direct_match.group(2)
                    key = _normalize_package_key(name, version)
                    
                    node = DependencyNode(
                        name=name,
                        version=version,
                        ecosystem="RubyGems",
                        is_direct=True,
                        depth=0,
                    )
                    
                    tree.nodes[key] = node
                    tree.direct_deps.add(key)
                    current_gem = name
                    
                # Transitive dependency: "      dep_name (version)"
                trans_match = re.match(r'^      ([a-zA-Z0-9_-]+)', line)
                if trans_match and current_gem:
                    dep_name = trans_match.group(1)
                    # Find the corresponding node
                    for key, node in tree.nodes.items():
                        if node.name == current_gem:
                            node.requires.append(dep_name)
                            break
        
        # Build required_by relationships
        for key, node in tree.nodes.items():
            for req in node.requires:
                for other_key, other_node in tree.nodes.items():
                    if other_node.name == req:
                        other_node.required_by.append(node.name)
                        if not other_node.is_direct:
                            other_node.depth = node.depth + 1
                        break
        
        tree.total_count = len(tree.nodes)
        
    except Exception as e:
        logger.warning(f"Error parsing Gemfile.lock {lock_path}: {e}")
    
    return tree


def parse_composer_lock_tree(lock_path: Path) -> DependencyTree:
    """
    Parse composer.lock to build PHP dependency tree.
    """
    tree = DependencyTree(ecosystem="Packagist")
    
    try:
        data = json.loads(lock_path.read_text(encoding='utf-8', errors='ignore') or "{}")
        
        # Process packages and packages-dev
        for section, is_dev in [("packages", False), ("packages-dev", True)]:
            for pkg in data.get(section, []):
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v")
                key = _normalize_package_key(name, version)
                
                requires = list(pkg.get("require", {}).keys())
                # Filter out PHP version requirements
                requires = [r for r in requires if not r.startswith("php") and not r.startswith("ext-")]
                
                node = DependencyNode(
                    name=name,
                    version=version,
                    ecosystem="Packagist",
                    is_direct=True,  # All in composer.lock are resolved
                    is_dev=is_dev,
                    requires=requires,
                )
                
                tree.nodes[key] = node
                
                if is_dev:
                    tree.dev_deps.add(key)
                else:
                    tree.direct_deps.add(key)
        
        # Build required_by relationships
        for key, node in tree.nodes.items():
            for req in node.requires:
                for other_key, other_node in tree.nodes.items():
                    if other_node.name == req:
                        other_node.required_by.append(node.name)
                        break
        
        _calculate_depths(tree)
        
        tree.total_count = len(tree.nodes)
        
    except Exception as e:
        logger.warning(f"Error parsing composer.lock {lock_path}: {e}")
    
    return tree


def _calculate_depths(tree: DependencyTree):
    """Calculate depth for each node based on required_by relationships."""
    # Nodes with no required_by are direct (depth 0)
    for key, node in tree.nodes.items():
        if not node.required_by:
            node.is_direct = True
            node.depth = 0
            tree.direct_deps.add(key)
    
    # BFS to calculate depths
    visited = set()
    queue = [(key, 0) for key in tree.direct_deps]
    
    while queue:
        key, depth = queue.pop(0)
        if key in visited:
            continue
        visited.add(key)
        
        node = tree.nodes.get(key)
        if node:
            node.depth = min(node.depth, depth) if node.depth > 0 else depth
            tree.max_depth = max(tree.max_depth, node.depth)
            
            # Add children
            for req_name in node.requires:
                for child_key, child_node in tree.nodes.items():
                    if child_node.name.lower() == req_name.lower():
                        if child_key not in visited:
                            queue.append((child_key, depth + 1))
                        break


def _build_relationships_and_depths(tree: DependencyTree):
    """Build required_by relationships and calculate depths."""
    # Build required_by
    for key, node in tree.nodes.items():
        for req in node.requires:
            for other_key, other_node in tree.nodes.items():
                if other_node.name.lower() == req.lower():
                    other_node.required_by.append(node.name)
                    break
    
    # Identify direct deps (not required by anything)
    for key, node in tree.nodes.items():
        if not node.required_by:
            node.is_direct = True
            tree.direct_deps.add(key)
    
    _calculate_depths(tree)


def parse_dependency_tree(source_root: Path) -> Dict[str, DependencyTree]:
    """
    Parse all dependency lock files in a project and build dependency trees.
    
    Returns dict mapping ecosystem to DependencyTree.
    """
    trees: Dict[str, DependencyTree] = {}
    
    # npm
    for lock_file in source_root.rglob("package-lock.json"):
        if "node_modules" in str(lock_file):
            continue
        tree = parse_npm_lock_tree(lock_file)
        if tree.nodes:
            trees["npm"] = tree
            break  # Use first found
    
    # Python - Pipfile.lock
    for lock_file in source_root.rglob("Pipfile.lock"):
        tree = parse_pipfile_lock_tree(lock_file)
        if tree.nodes:
            trees["PyPI"] = tree
            break
    
    # Python - poetry.lock
    if "PyPI" not in trees:
        for lock_file in source_root.rglob("poetry.lock"):
            tree = parse_poetry_lock_tree(lock_file)
            if tree.nodes:
                trees["PyPI"] = tree
                break
    
    # Rust
    for lock_file in source_root.rglob("Cargo.lock"):
        tree = parse_cargo_lock_tree(lock_file)
        if tree.nodes:
            trees["crates.io"] = tree
            break
    
    # Ruby
    for lock_file in source_root.rglob("Gemfile.lock"):
        tree = parse_gemfile_lock_tree(lock_file)
        if tree.nodes:
            trees["RubyGems"] = tree
            break
    
    # PHP
    for lock_file in source_root.rglob("composer.lock"):
        if "vendor" in str(lock_file):
            continue
        tree = parse_composer_lock_tree(lock_file)
        if tree.nodes:
            trees["Packagist"] = tree
            break
    
    total_deps = sum(t.total_count for t in trees.values())
    logger.info(f"Parsed dependency trees for {len(trees)} ecosystems, {total_deps} total packages")
    
    return trees


def find_dependency_paths(
    tree: DependencyTree, 
    target_name: str, 
    target_version: Optional[str] = None
) -> List[List[str]]:
    """
    Find all paths from direct dependencies to a target package.
    
    Returns list of paths, where each path is a list of package names
    from direct dep to target.
    """
    paths: List[List[str]] = []
    
    # Find the target node
    target_key = None
    for key, node in tree.nodes.items():
        if node.name.lower() == target_name.lower():
            if target_version is None or node.version == target_version:
                target_key = key
                break
    
    if not target_key:
        return paths
    
    target_node = tree.nodes[target_key]
    
    # If it's a direct dependency, path is just itself
    if target_node.is_direct:
        return [[target_name]]
    
    # BFS from target back to direct deps
    def find_paths_to_root(current: str, path: List[str], visited: Set[str]):
        if current in visited:
            return
        visited.add(current)
        
        node = None
        for k, n in tree.nodes.items():
            if n.name.lower() == current.lower():
                node = n
                break
        
        if not node:
            return
        
        new_path = [current] + path
        
        if node.is_direct:
            paths.append(new_path)
            return
        
        for parent in node.required_by:
            find_paths_to_root(parent, new_path, visited.copy())
    
    find_paths_to_root(target_name, [], set())
    
    return paths


def analyze_vulnerable_dependencies(
    trees: Dict[str, DependencyTree],
    vulnerabilities: List[Any]  # List of Vulnerability models
) -> List[TransitiveDependencyInfo]:
    """
    Analyze vulnerabilities in context of dependency trees.
    
    For each vulnerability, determine:
    - If it's in a direct or transitive dependency
    - The dependency chain(s) to reach it
    - Which direct dependency pulls it in
    """
    results: List[TransitiveDependencyInfo] = []
    
    for vuln in vulnerabilities:
        # Get dependency info
        dep = vuln.dependency if hasattr(vuln, 'dependency') else None
        if not dep:
            continue
        
        dep_name = dep.name
        dep_version = dep.version
        ecosystem = dep.ecosystem
        
        # Find the tree for this ecosystem
        tree = trees.get(ecosystem)
        if not tree:
            continue
        
        # Find paths to this dependency
        paths = find_dependency_paths(tree, dep_name, dep_version)
        
        if not paths:
            # Not in tree (might be from manifest without lock file)
            continue
        
        # Determine if direct or transitive
        is_direct = any(len(p) == 1 for p in paths)
        
        # Get depth and root dependency
        min_depth = min(len(p) for p in paths)
        root_deps = set(p[0] for p in paths if p)
        
        info = TransitiveDependencyInfo(
            vulnerable_package=dep_name,
            vulnerable_version=dep_version or "unknown",
            vulnerability_id=vuln.external_id,
            is_direct=is_direct,
            depth=min_depth - 1,  # 0 = direct
            dependency_chain=paths[0] if paths else [dep_name],
            root_dependency=list(root_deps)[0] if root_deps else dep_name,
            all_paths=paths,
        )
        
        results.append(info)
    
    return results


def get_dependency_tree_summary(trees: Dict[str, DependencyTree]) -> Dict[str, Any]:
    """
    Get a summary of the dependency trees for reporting.
    """
    summary = {
        "ecosystems": {},
        "total_packages": 0,
        "total_direct": 0,
        "total_transitive": 0,
        "max_depth": 0,
    }
    
    for ecosystem, tree in trees.items():
        direct_count = len(tree.direct_deps)
        transitive_count = tree.total_count - direct_count
        
        summary["ecosystems"][ecosystem] = {
            "total": tree.total_count,
            "direct": direct_count,
            "transitive": transitive_count,
            "max_depth": tree.max_depth,
        }
        
        summary["total_packages"] += tree.total_count
        summary["total_direct"] += direct_count
        summary["total_transitive"] += transitive_count
        summary["max_depth"] = max(summary["max_depth"], tree.max_depth)
    
    return summary


def enrich_vulnerability_with_tree_info(
    vuln_finding: Any,
    tree_info: TransitiveDependencyInfo
) -> Dict:
    """
    Enrich a vulnerability finding with dependency tree information.
    
    Adds:
    - is_transitive: bool
    - dependency_depth: int
    - dependency_chain: list
    - root_dependency: str
    """
    details = dict(vuln_finding.details) if vuln_finding.details else {}
    
    details["is_transitive"] = not tree_info.is_direct
    details["dependency_depth"] = tree_info.depth
    details["dependency_chain"] = tree_info.dependency_chain
    details["root_dependency"] = tree_info.root_dependency
    details["all_dependency_paths"] = tree_info.all_paths[:5]  # Limit to 5 paths
    
    return details
