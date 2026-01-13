# Security Wordlists

This directory contains comprehensive wordlists for security testing and fuzzing operations.

## Built-in Wordlists

| File | Category | Description | Entries |
|------|----------|-------------|---------|
| `passwords_top10k.txt` | Passwords | Curated top 10,000 passwords from breach databases | ~10,000 |
| `sqli_comprehensive.txt` | SQL Injection | Auth bypass, UNION, time-based, error-based payloads | ~400+ |
| `xss_comprehensive.txt` | XSS | Basic, encoded, event handlers, polyglot, filter bypass | ~300+ |
| `path_traversal_comprehensive.txt` | Path Traversal | LFI/RFI, encoded variants, PHP wrappers | ~200+ |
| `command_injection_comprehensive.txt` | Command Injection | Unix/Windows, blind, reverse shells | ~200+ |
| `ssti_comprehensive.txt` | SSTI | Jinja2, Twig, FreeMarker, Velocity, Thymeleaf, ERB | ~150+ |
| `nosqli_comprehensive.txt` | NoSQL Injection | MongoDB, CouchDB, Redis, LDAP | ~150+ |
| `ssrf_comprehensive.txt` | SSRF | Localhost, cloud metadata, protocols | ~300+ |
| `xxe_comprehensive.txt` | XXE | Basic, blind OOB, wrappers, SVG, SOAP | ~100+ |
| `directories_comprehensive.txt` | Directory Discovery | Admin panels, APIs, CMS, sensitive files | ~400+ |
| `usernames_common.txt` | Usernames | Admin, service accounts, default accounts | ~300+ |

## Usage

### In Python

```python
from services.wordlist_service import (
    get_wordlist_service,
    WordlistCategory,
    get_payloads,
    get_passwords
)

# Get wordlist service
service = get_wordlist_service()

# Get SQLi payloads
sqli_payloads = service.get_wordlist(WordlistCategory.SQLI)

# Get payloads by technique name
payloads = get_payloads("xss", limit=100)

# Get passwords
passwords = get_passwords(limit=1000)

# Get combined wordlists
combined = service.get_combined_wordlist([
    WordlistCategory.SQLI,
    WordlistCategory.XSS
])

# Stream large wordlists
for chunk in service.stream_wordlist(WordlistCategory.PASSWORDS, chunk_size=1000):
    process_passwords(chunk)
```

## Adding External Wordlists

### Option 1: Docker Volume Mount

Mount your wordlists directory to `/wordlists`:

```yaml
# docker-compose.yml
services:
  backend:
    volumes:
      - /path/to/your/wordlists:/wordlists:ro
```

### Option 2: SecLists Integration

If you have SecLists installed:

```bash
# Kali Linux
sudo apt install seclists
# Wordlists available at /usr/share/seclists

# Manual installation
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

### Option 3: Custom Wordlist Files

Place additional wordlist files in this directory. They will be automatically discovered.

### Supported External Wordlist Locations

The service automatically searches these paths:
- `/wordlists` (Docker volume mount)
- `/usr/share/wordlists` (Kali Linux)
- `/usr/share/seclists` (SecLists)
- `./wordlists` (Relative to working directory)

## Using RockYou.txt

RockYou.txt (~133MB, 14+ million passwords) is too large to include in the repository.
The built-in `passwords_top10k.txt` contains a curated subset of the most common passwords.

To use the full RockYou:

1. Download or obtain `rockyou.txt`
2. Mount via Docker volume:
   ```yaml
   volumes:
     - /path/to/rockyou.txt:/wordlists/rockyou.txt:ro
   ```
3. Use in code:
   ```python
   passwords = service.load_external_file("rockyou.txt", limit=100000)
   ```

## Wordlist Format

- One entry per line
- Lines starting with `#` are treated as comments
- Empty lines are ignored
- UTF-8 encoding

## Contributing

To add new wordlists:

1. Create a `.txt` file with entries (one per line)
2. Add descriptive comments at the top with `#`
3. Update `BUILTIN_WORDLISTS` in `wordlist_service.py` if needed
4. Update this README

## Security Considerations

- These wordlists are for **authorized security testing only**
- Never use against systems without permission
- Some payloads may trigger security alerts
- Use responsibly and ethically

## Sources

Built-in wordlists are compiled from:
- OWASP testing guidelines
- SecLists project (curated)
- PayloadsAllTheThings
- Real-world penetration testing experience
- Breach database analysis (for password lists)

## License

Wordlists are provided for security testing purposes.
Original sources retain their respective licenses.
