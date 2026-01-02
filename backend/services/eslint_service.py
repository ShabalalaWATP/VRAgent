"""
ESLint Security Service

Runs ESLint with security-focused plugins to detect JavaScript/TypeScript vulnerabilities.
"""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ESLintFinding:
    """Represents an ESLint security finding."""
    rule_id: str
    severity: str
    message: str
    file_path: str
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    category: str = "security"


# ESLint security rules mapping to severity
SECURITY_RULES = {
    # eslint-plugin-security rules
    'security/detect-buffer-noassert': 'medium',
    'security/detect-child-process': 'high',
    'security/detect-disable-mustache-escape': 'high',
    'security/detect-eval-with-expression': 'critical',
    'security/detect-new-buffer': 'medium',
    'security/detect-no-csrf-before-method-override': 'high',
    'security/detect-non-literal-fs-filename': 'medium',
    'security/detect-non-literal-regexp': 'medium',
    'security/detect-non-literal-require': 'high',
    'security/detect-object-injection': 'high',
    'security/detect-possible-timing-attacks': 'medium',
    'security/detect-pseudoRandomBytes': 'medium',
    'security/detect-unsafe-regex': 'medium',
    
    # eslint-plugin-no-unsanitized rules
    'no-unsanitized/method': 'high',
    'no-unsanitized/property': 'high',
    
    # eslint-plugin-xss rules
    'xss/no-location-href-assign': 'high',
    'xss/no-mixed-html': 'medium',
    
    # Built-in ESLint rules with security implications
    'no-eval': 'critical',
    'no-implied-eval': 'critical',
    'no-new-func': 'high',
    'no-script-url': 'high',
}

# Default ESLint config for security scanning (flat config format for ESLint v9+)
# Uses only built-in rules for maximum compatibility
DEFAULT_ESLINT_FLAT_CONFIG = """
export default [
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: {
        ecmaFeatures: {
          jsx: true
        }
      }
    },
    rules: {
      // Code execution risks
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      
      // Dangerous patterns
      'no-proto': 'error',
      'no-extend-native': 'error',
      'no-iterator': 'error',
      'no-restricted-globals': ['error', 'event', 'fdescribe'],
      
      // Code quality that impacts security
      'no-undef': 'error',
      'no-unused-vars': 'warn',
      'no-use-before-define': 'error',
      'no-shadow': 'warn',
      'no-redeclare': 'error',
      
      // Potential logic errors
      'eqeqeq': ['error', 'always'],
      'no-eq-null': 'error',
      'no-self-compare': 'error',
      'no-sequences': 'error',
      'no-throw-literal': 'error',
      'no-unmodified-loop-condition': 'error',
      'no-useless-concat': 'warn',
      
      // Regex safety
      'no-control-regex': 'error',
      'no-invalid-regexp': 'error',
      'no-misleading-character-class': 'error'
    }
  }
];
"""

# Extended config that uses security plugin (globally installed)
# Uses CommonJS format to work with global modules
EXTENDED_ESLINT_FLAT_CONFIG = """
const security = require('eslint-plugin-security');

module.exports = [
  security.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: {
        ecmaFeatures: {
          jsx: true
        }
      }
    },
    rules: {
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error'
    }
  }
];
"""

# Legacy config for ESLint v8 and below
DEFAULT_ESLINT_CONFIG = {
    "env": {
        "browser": True,
        "node": True,
        "es2021": True
    },
    "parserOptions": {
        "ecmaVersion": "latest",
        "sourceType": "module",
        "ecmaFeatures": {
            "jsx": True
        }
    },
    "plugins": ["security"],
    "extends": ["plugin:security/recommended"],
    "rules": {
        "no-eval": "error",
        "no-implied-eval": "error",
        "no-new-func": "error",
        "no-script-url": "error",
        "security/detect-buffer-noassert": "error",
        "security/detect-child-process": "warn",
        "security/detect-disable-mustache-escape": "error",
        "security/detect-eval-with-expression": "error",
        "security/detect-new-buffer": "warn",
        "security/detect-no-csrf-before-method-override": "error",
        "security/detect-non-literal-fs-filename": "warn",
        "security/detect-non-literal-regexp": "warn",
        "security/detect-non-literal-require": "warn",
        "security/detect-object-injection": "warn",
        "security/detect-possible-timing-attacks": "warn",
        "security/detect-pseudoRandomBytes": "warn",
        "security/detect-unsafe-regex": "warn"
    }
}


def check_eslint_available() -> bool:
    """Check if ESLint is available in the system."""
    try:
        result = subprocess.run(
            ['npx', 'eslint', '--version'],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_node_available() -> bool:
    """Check if Node.js is available in the system."""
    try:
        result = subprocess.run(
            ['node', '--version'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_js_files(directory: str) -> List[str]:
    """Get all JavaScript/TypeScript files in a directory."""
    js_extensions = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
    js_files = []
    
    for root, dirs, files in os.walk(directory):
        # Skip node_modules and other ignored directories
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'dist', 'build', 'coverage']]
        
        for file in files:
            if any(file.endswith(ext) for ext in js_extensions):
                js_files.append(os.path.join(root, file))
    
    return js_files


def map_eslint_severity(eslint_severity: int) -> str:
    """Map ESLint severity (1=warn, 2=error) to our severity levels."""
    return 'high' if eslint_severity == 2 else 'medium'


def get_rule_severity(rule_id: str, eslint_severity: int) -> str:
    """Get severity for a rule, using our mapping or falling back to ESLint's."""
    if rule_id in SECURITY_RULES:
        return SECURITY_RULES[rule_id]
    return map_eslint_severity(eslint_severity)


def create_temp_eslint_config(directory: str, use_plugin: bool = False) -> str:
    """Create a temporary ESLint config file for security scanning (flat config for v9+)."""
    # Use .cjs for CommonJS format (works better with global modules)
    config_path = os.path.join(directory, 'eslint.config.cjs' if use_plugin else 'eslint.config.mjs')
    config_content = EXTENDED_ESLINT_FLAT_CONFIG if use_plugin else DEFAULT_ESLINT_FLAT_CONFIG
    with open(config_path, 'w') as f:
        f.write(config_content)
    return config_path


def parse_eslint_output(output: str, base_dir: str) -> List[ESLintFinding]:
    """Parse ESLint JSON output into findings."""
    findings = []
    
    try:
        results = json.loads(output)
        
        for file_result in results:
            file_path = file_result.get('filePath', '')
            # Make path relative to base directory
            if file_path and file_path.startswith(base_dir):
                file_path = file_path[len(base_dir):].lstrip(os.sep)
            
            for message in file_result.get('messages', []):
                rule_id = message.get('ruleId') or 'unknown'
                
                # Skip non-security rules if not in our list
                if not any(rule_id.startswith(prefix) for prefix in ['security/', 'no-unsanitized/', 'xss/', 'no-eval', 'no-implied-eval', 'no-new-func', 'no-script-url']):
                    continue
                
                severity = get_rule_severity(rule_id, message.get('severity', 1))
                
                finding = ESLintFinding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message.get('message', ''),
                    file_path=file_path,
                    line=message.get('line', 0),
                    column=message.get('column', 0),
                    end_line=message.get('endLine'),
                    end_column=message.get('endColumn'),
                )
                findings.append(finding)
                
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse ESLint output: {e}")
    
    return findings


def run_eslint_security_scan(
    directory: str,
    timeout: int = 300,
    install_plugins: bool = True,
) -> List[ESLintFinding]:
    """
    Run ESLint with security plugins on a directory.
    
    Args:
        directory: Directory to scan
        timeout: Timeout in seconds
        install_plugins: Whether to install security plugins if needed
        
    Returns:
        List of ESLintFinding objects
    """
    if not check_node_available():
        logger.warning("Node.js not available, skipping ESLint security scan")
        return []
    
    # Get JS/TS files
    js_files = get_js_files(directory)
    if not js_files:
        logger.info("No JavaScript/TypeScript files found to scan")
        return []
    
    logger.info(f"Running ESLint security scan on {len(js_files)} files")
    
    try:
        # Try extended config first (with security plugin)
        # Fall back to basic config if it fails
        config_path = create_temp_eslint_config(directory, use_plugin=True)
        
        try:
            # Run ESLint
            cmd = [
                'npx', 'eslint',
                '--config', config_path,
                '--format', 'json',
                '--no-error-on-unmatched-pattern',
                '--ignore-pattern', '*.test.js',
                '--ignore-pattern', '*.test.ts',
                '--ignore-pattern', '*.spec.js',
                '--ignore-pattern', '*.spec.ts',
                '--ignore-pattern', '__tests__/**',
                '--ignore-pattern', 'tests/**',
                '--ignore-pattern', 'test/**',
                '--ignore-pattern', '**/*.mock.js',
                '--ignore-pattern', '**/*.mock.ts',
            ]
            cmd.extend(js_files[:100])  # Limit files to avoid command line length issues
            
            result = subprocess.run(
                cmd,
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, 'NODE_PATH': '/usr/lib/node_modules'}  # Find globally installed plugins
            )
            
            # Check if ESLint ran successfully (ignore lint errors, they're expected)
            if result.stdout and result.stdout.strip().startswith('['):
                findings = parse_eslint_output(result.stdout, directory)
                logger.info(f"ESLint security scan found {len(findings)} issues (with security plugin)")
                return findings
            else:
                # Plugin failed, try basic config
                logger.warning(f"ESLint with security plugin failed: {result.stderr[:200] if result.stderr else 'no output'}")
                if os.path.exists(config_path):
                    os.remove(config_path)
                config_path = create_temp_eslint_config(directory, use_plugin=False)
                
                # Rebuild command with new config
                cmd = [
                    'npx', 'eslint',
                    '--config', config_path,
                    '--format', 'json',
                    '--no-error-on-unmatched-pattern',
                ]
                cmd.extend(js_files[:100])
                
                result = subprocess.run(
                    cmd,
                    cwd=directory,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                
                if result.stdout and result.stdout.strip().startswith('['):
                    findings = parse_eslint_output(result.stdout, directory)
                    logger.info(f"ESLint security scan found {len(findings)} issues (basic rules)")
                    return findings
                else:
                    if result.stderr:
                        logger.warning(f"ESLint stderr: {result.stderr[:500]}")
                    return []
            
        finally:
            # Cleanup temp config
            if os.path.exists(config_path):
                os.remove(config_path)
                
    except subprocess.TimeoutExpired:
        logger.warning(f"ESLint scan timed out after {timeout} seconds")
        return []
    except Exception as e:
        logger.error(f"ESLint security scan failed: {e}")
        return []


def scan_single_file(file_path: str) -> List[ESLintFinding]:
    """
    Run ESLint security scan on a single file.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        List of ESLintFinding objects
    """
    if not os.path.exists(file_path):
        return []
    
    directory = os.path.dirname(file_path)
    
    if not check_node_available():
        return []
    
    # Create temporary config
    config_path = create_temp_eslint_config(directory)
    
    try:
        cmd = [
            'npx', 'eslint',
            '--config', config_path,
            '--format', 'json',
            '--no-error-on-unmatched-pattern',
            file_path,
        ]
        
        result = subprocess.run(
            cmd,
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        return parse_eslint_output(result.stdout, directory)
        
    except Exception as e:
        logger.warning(f"ESLint scan failed for {file_path}: {e}")
        return []
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)


def summarize_findings(findings: List[ESLintFinding]) -> Dict[str, Any]:
    """Generate a summary of ESLint findings."""
    if not findings:
        return {
            'total_count': 0,
            'by_severity': {},
            'by_rule': {},
            'files_affected': 0,
        }
    
    by_severity: Dict[str, int] = {}
    by_rule: Dict[str, int] = {}
    files = set()
    
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
        files.add(finding.file_path)
    
    return {
        'total_count': len(findings),
        'by_severity': by_severity,
        'by_rule': by_rule,
        'files_affected': len(files),
    }
