"""
Tests for the new dependency parsers (Go, Ruby, Rust, PHP).
"""

import tempfile
from pathlib import Path

import pytest

from backend.services.dependency_service import (
    _parse_go_mod,
    _parse_gemfile,
    _parse_gemfile_lock,
    _parse_cargo_toml,
    _parse_cargo_lock,
    _parse_composer_json,
    _parse_composer_lock,
)


class TestGoModParser:
    """Tests for Go go.mod parser."""

    def test_parse_go_mod_require_block(self, tmp_path):
        """Test parsing go.mod with require block."""
        go_mod = """module github.com/example/app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
    golang.org/x/crypto v0.14.0 // indirect
)
"""
        (tmp_path / "go.mod").write_text(go_mod)
        deps = _parse_go_mod(1, tmp_path / "go.mod", tmp_path)

        assert len(deps) == 3
        assert deps[0].name == "github.com/gin-gonic/gin"
        assert deps[0].version == "v1.9.1"
        assert deps[0].ecosystem == "Go"

    def test_parse_go_mod_single_require(self, tmp_path):
        """Test parsing go.mod with single-line require."""
        go_mod = """module github.com/example/app

go 1.21

require github.com/spf13/cobra v1.7.0
"""
        (tmp_path / "go.mod").write_text(go_mod)
        deps = _parse_go_mod(1, tmp_path / "go.mod", tmp_path)

        assert len(deps) == 1
        assert deps[0].name == "github.com/spf13/cobra"
        assert deps[0].version == "v1.7.0"


class TestGemfileParser:
    """Tests for Ruby Gemfile parser."""

    def test_parse_gemfile_basic(self, tmp_path):
        """Test parsing Gemfile with various gem declarations."""
        gemfile = '''source "https://rubygems.org"

gem "rails", "~> 7.0"
gem "pg", ">= 1.0"
gem 'sidekiq'
gem "puma", "~> 5.0"
'''
        (tmp_path / "Gemfile").write_text(gemfile)
        deps = _parse_gemfile(1, tmp_path / "Gemfile", tmp_path)

        assert len(deps) == 4
        names = [d.name for d in deps]
        assert "rails" in names
        assert "pg" in names
        assert "sidekiq" in names
        assert "puma" in names
        
        rails = next(d for d in deps if d.name == "rails")
        assert rails.version == "~> 7.0"
        assert rails.ecosystem == "RubyGems"
        
        sidekiq = next(d for d in deps if d.name == "sidekiq")
        assert sidekiq.version is None


class TestGemfileLockParser:
    """Tests for Ruby Gemfile.lock parser."""

    def test_parse_gemfile_lock(self, tmp_path):
        """Test parsing Gemfile.lock with precise versions."""
        gemfile_lock = """GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.4)
      actionpack (= 7.0.4)
    actionpack (7.0.4)
      rack (~> 2.0)
    rails (7.0.4)
      actioncable (= 7.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0)
"""
        (tmp_path / "Gemfile.lock").write_text(gemfile_lock)
        deps = _parse_gemfile_lock(1, tmp_path / "Gemfile.lock", tmp_path)

        assert len(deps) == 3
        rails = next(d for d in deps if d.name == "rails")
        assert rails.version == "7.0.4"
        assert rails.ecosystem == "RubyGems"


class TestCargoTomlParser:
    """Tests for Rust Cargo.toml parser."""

    def test_parse_cargo_toml_simple(self, tmp_path):
        """Test parsing Cargo.toml with simple version strings."""
        cargo_toml = """[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }

[dev-dependencies]
criterion = "0.5"
"""
        (tmp_path / "Cargo.toml").write_text(cargo_toml)
        deps = _parse_cargo_toml(1, tmp_path / "Cargo.toml", tmp_path)

        assert len(deps) == 3
        
        serde = next(d for d in deps if d.name == "serde")
        assert serde.version == "1.0"
        assert serde.ecosystem == "crates.io"
        
        tokio = next(d for d in deps if d.name == "tokio")
        assert tokio.version == "1.0"


class TestCargoLockParser:
    """Tests for Rust Cargo.lock parser."""

    def test_parse_cargo_lock(self, tmp_path):
        """Test parsing Cargo.lock with exact versions."""
        cargo_lock = """[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.35.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
        (tmp_path / "Cargo.lock").write_text(cargo_lock)
        deps = _parse_cargo_lock(1, tmp_path / "Cargo.lock", tmp_path)

        assert len(deps) == 2
        
        serde = next(d for d in deps if d.name == "serde")
        assert serde.version == "1.0.193"
        assert serde.ecosystem == "crates.io"


class TestComposerJsonParser:
    """Tests for PHP composer.json parser."""

    def test_parse_composer_json(self, tmp_path):
        """Test parsing composer.json with require and require-dev."""
        composer_json = """{
    "require": {
        "php": "^8.1",
        "laravel/framework": "^10.0",
        "guzzlehttp/guzzle": "^7.2"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.0"
    }
}
"""
        (tmp_path / "composer.json").write_text(composer_json)
        deps = _parse_composer_json(1, tmp_path / "composer.json", tmp_path)

        # PHP itself is skipped
        assert len(deps) == 3
        names = [d.name for d in deps]
        assert "laravel/framework" in names
        assert "guzzlehttp/guzzle" in names
        assert "phpunit/phpunit" in names
        assert "php" not in names
        
        laravel = next(d for d in deps if d.name == "laravel/framework")
        assert laravel.version == "^10.0"
        assert laravel.ecosystem == "Packagist"


class TestComposerLockParser:
    """Tests for PHP composer.lock parser."""

    def test_parse_composer_lock(self, tmp_path):
        """Test parsing composer.lock with precise versions."""
        composer_lock = """{
    "packages": [
        {
            "name": "laravel/framework",
            "version": "v10.38.2"
        },
        {
            "name": "guzzlehttp/guzzle",
            "version": "7.8.1"
        }
    ],
    "packages-dev": [
        {
            "name": "phpunit/phpunit",
            "version": "10.5.5"
        }
    ]
}
"""
        (tmp_path / "composer.lock").write_text(composer_lock)
        deps = _parse_composer_lock(1, tmp_path / "composer.lock", tmp_path)

        assert len(deps) == 3
        
        # v prefix should be stripped
        laravel = next(d for d in deps if d.name == "laravel/framework")
        assert laravel.version == "10.38.2"
        assert laravel.ecosystem == "Packagist"
