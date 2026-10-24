# Findings Database

`port_findings.json` contains safe, read-only checks that the findings engine runs against discovered open ports.

## Rules

All checks are **read-only and non-destructive**. The following are never included:

- Brute force or password attacks
- Default credential testing
- Exploit execution or write operations
- Any command that modifies target state

## Check Types

| Type | Description |
|------|-------------|
| `http_header_missing` | Check if a security header is absent |
| `http_header_value` | Check if a header has an insecure value |
| `http_get_match` | GET an endpoint, check if response contains a string |
| `http_get_status` | GET an endpoint, check if it returns 200 |
| `command_match` | Run a command, check if output contains a string |
| `command_no_match` | Run a command, check if output does NOT contain a string |
| `ssl_check` | OpenSSL certificate and cipher checks |
| `banner_match` | Analyze nmap service banner for known issues |
| `nmap_script` | Run a specific nmap NSE script |

## Adding Findings

Add new entries to the `findings` array in `port_findings.json`. Each entry requires:

- `id` — unique integer
- `name` — human-readable finding name
- `port` — array of applicable ports
- `severity` — Critical, High, Medium, Low, or Info
- `cvss` — CVSS score (float)
- `check` — object with `type`, `command` (using `{target}` and `{port}` placeholders), and type-specific fields
