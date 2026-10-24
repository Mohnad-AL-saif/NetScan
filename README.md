# NetScan — Network Service Discovery & Automated Findings Tool

A web-based tool for system administrators to audit their own infrastructure. It wraps Nmap for service discovery and automatically runs safe, read-only checks against discovered services to identify misconfigurations.

## Features

- **Nmap Integration** — Service/version detection with XML parsing
- **Automated Findings Engine** — 116 safe, read-only checks across 18 categories
- **Dark-themed Web UI** — Dashboard, scan management, findings detail, scan comparison
- **Multi-user Auth** — Session-based authentication with admin/user roles
- **Severity Tracking** — Critical, High, Medium, Low, Info with color-coded badges
- **Filtering & Export** — Filter findings by severity, port, category; export as JSON

## Quick Start

```bash
# Install nmap (if not already installed)
sudo apt install nmap

# Install Python dependencies
cd web
pip install -r requirements.txt

# Run the app
python app.py
```

Open http://localhost:5000 and log in with:
- **Username:** admin
- **Password:** admin123

## Project Structure

```
├── web/
│   ├── app.py              # Flask routes + main app
│   ├── models.py           # SQLite models, auth, settings
│   ├── nmap_runner.py      # Nmap subprocess wrapper + XML parser
│   ├── findings_engine.py  # Auto-check engine
│   ├── requirements.txt
│   └── templates/          # 10 Jinja2 templates
├── findings/
│   └── port_findings.json  # 116 safe finding checks
└── README.md
```

## Safety

All finding checks are **read-only and non-destructive**:
- No brute force or password testing
- No exploit execution or write operations
- All subprocess calls have timeouts
- HTTP checks use GET/HEAD only (except GraphQL introspection POST)
