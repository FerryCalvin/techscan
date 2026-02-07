# TechScan Developer Guide

Welcome to the TechScan development documentation. This guide provides technical details on the architecture, codebase structure, and workflows for extending the platform.

## 🏗️ Architecture Overview

TechScan uses a robust tiered architecture designed for speed and accuracy.

### Scanning Pipeline

1.  **Tier 0 (Heuristic / Fast Mode)**
    - **Engine**: Pure Python (`app/heuristic_fast.py`)
    - **Mechanism**: Analyzes HTTP headers (`Server`, `X-Powered-By`) and raw HTML source code using regex.
    - **Speed**: ~500ms per domain.
    - **Use Case**: Quick initial assessment, identifying static sites.

2.  **Tier 1 (Wappalyzer-Local / Python)**
    - **Engine**: Python (`app/wapp_local.py`)
    - **Mechanism**: Applies Wappalyzer's extensive regex rules directly within Python.
    - **Speed**: ~1s per domain.
    - **Use Case**: Detecting CMS, frameworks, and tools without browser overhead.

3.  **Tier 2 (Unified / Deep Mode)**
    - **Engine**: Node.js + Puppeteer (`node_scanner/scanner.js`)
    - **Mechanism**: Launches a headless browser to render the page, execute JavaScript, and inspect the DOM.
    - **Speed**: 15s - 45s per domain.
    - **Use Case**: Detecting SPAs (React, Vue), dynamic assets, and fully-rendered content.

### Database Schema
The core data models are managed via raw SQL in `app/db.py` to ensure performance.
- **scans**: Stores every scan result, including raw metadata, duration, and detected technologies.
- **domain_techs**: A denormalized table for fast aggregation and analytics queries.
- **domain_groups**: Manages user-defined groupings of domains for organization.

---

## 📂 Project Structure

```
techscan/
├── app/
│   ├── routes/          # API endpoints (Blueprint modules)
│   ├── static/          # CSS, JS, and image assets
│   ├── templates/       # Jinja2 HTML templates
│   ├── db.py            # Database connection & queries
│   ├── scan_utils.py    # Core scanning orchestration logic
│   └── ...
├── node_scanner/        # Node.js based scanning scripts
├── scripts/             # Utility scripts (seeding, maintenance)
├── tests/               # Pytest test suite
├── run.py               # Application entry point
└── requirements.txt     # Python dependencies
```

---

## 🧪 Testing

We use `pytest` for backend testing. Ensure your virtual environment is active.

### Running Tests
```bash
# Run all tests
pytest

# Run a specific test file
pytest tests/test_scan_routes.py

# Run tests with output
pytest -v -s
```

### Writing Tests
- Place new tests in the `tests/` directory.
- Use `conftest.py` for shared fixtures (e.g., mock DB connections).
- Mock external calls (like network requests or Node.js subprocesses) to keep tests fast and deterministic.

---

## 🤝 Contribution Workflow

1.  **Fork the repository** and clone it locally.
2.  **Create a branch** for your feature or fix: `git checkout -b feature/new-scanner`.
3.  **Implement your changes**, ensuring you follow the existing code style (PEP 8 for Python).
4.  **Add tests** for any new functionality.
5.  **Run formatting/linting** (e.g., `ruff check .`) to ensure code quality.
6.  **Push your branch** and submit a Pull Request.

---

## 🐛 Debugging

- **Logs**: Application logs are printed to `stdout`.
- **Debug Mode**: Run the app with `FLASK_DEBUG=1` for hot-reloading and detailed error pages.
- **Node Debugging**: You can run the Node scanner manually with `node node_scanner/scanner.js --url ...` to see raw Puppeteer output.
