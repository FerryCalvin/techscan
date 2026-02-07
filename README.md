# TechScan - Modern Web Technology Scanner

TechScan is a comprehensive web technology scanner that combines **heuristic detection**, **local pattern matching** (Wappalyzer-python), and **browser-based deep analysis** (Puppeteer) into a **Unified Scanning Pipeline**.

It provides a rich dashboard for visualizing technology trends, monitoring server health, and managing bulk scan operations.



## 📚 Documentation

TechScan documentation is organized into three distinct guides to help you get started quickly:

### 🚀 [User Guide](docs/user_guide.md)
**For End Users & Analysts**
- How to use the Dashboard and run single/bulk scans.
- Understanding reports, analytics, and historical data.
- Automating workflows with the REST API.

### 🛠️ [Setup Guide](docs/setup_guide.md)
**For Administrators & DevOps**
- Installation instructions (Python, Node.js, PostgreSQL).
- Configuration (`.env`, database setup).
- Deployment options (Local, Docker).

### 👨‍💻 [Developer Guide](docs/developer_guide.md)
**For Contributors**
- Project architecture and code structure.
- Running tests and debugging.
- How to contribute new features or scanners.

---

## ⚡ Quick Start (Local)

1.  **Clone & Setup Python Environment**
    ```powershell
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    ```

2.  **Install Node.js Dependencies**
    ```powershell
    cd node_scanner
    npm install
    cd ..
    ```

3.  **Run the Application**
    ```powershell
    python run.py
    ```
    Access the dashboard at `http://localhost:5000`.

---

## 🤝 Contributing
We welcome contributions! Please see the [Developer Guide](docs/developer_guide.md) for details on our workflow and coding standards.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
