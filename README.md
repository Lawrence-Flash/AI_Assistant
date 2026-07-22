# AI-Cybersecurity Assistant

An advanced, AI-powered network scanning and OSINT monitoring tool designed for both CLI and Web interfaces. It leverages `nmap` for robust network reconnaissance, `dnspython`/`python-whois` for Open-Source Intelligence (OSINT), and Google's Gemini AI to analyze scan results, providing actionable cybersecurity insights.

---

## 🚀 Key Features

- **Dual Interfaces**: Use the sleek "hacker-style" terminal interface (`cli.py`) or the modern, responsive web dashboard (`app.py`).
- **AI Security Analysis**: Automatically analyzes raw `nmap` and OSINT output using Gemini AI to identify vulnerabilities, explain open ports, and provide remediation steps.
- **OSINT Enrichment**: Automatically fetches Whois data and DNS records (A, MX, etc.) to provide context alongside network scans.
- **Continuous Monitoring & Webhooks**: Add targets to a background Watchlist. The system will scan them periodically and fire a Discord/Slack Webhook alert (along with AI analysis) if the attack surface changes (e.g., a new port opens).
- **History Tracking**: Saves all previous scans and AI analysis reports to a local SQLite database for future review and diffing.

---

## 📋 Prerequisites

- Python 3.11+
- Nmap installed and available in your system's PATH.

---

## 🛠️ Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Lawrence-Flash/AI_Assistant.git
   cd AI_Assistant
   ```

2. **Install Dependencies**:
   Ensure you have all the required networking and web packages:
   ```bash
   pip install .
   ```

3. **Configure Environment Variables**:
   Open the `.env` file (or create one) and set your Gemini API key:
   ```bash
   GEMINI_API_KEY=your_api_key_here
   ```

---

## 💻 Usage

### 🌐 Web Dashboard (Recommended)
Run the Flask server to access the modern web interface:
```bash
python app.py
```
Then navigate to [http://127.0.0.1:5001](http://127.0.0.1:5001) in your browser. From here you can run scans, view OSINT data, chat with the AI, and configure your webhook settings!

### ⌨️ CLI Mode (Hacker Terminal)
Run the interactive rich-based command-line interface:
```bash
python cli.py
```

---

## 📁 Project Structure

```
AI_Assistant/
├── .env                 # API Keys (Do not commit to public repo)
├── app.py               # Flask web server & scheduled background jobs
├── cli.py               # Command-line interface
├── db.py                # SQLite database management (history, settings, watchlists)
├── utils.py             # Core logic (Nmap execution, OSINT gathering, AI analysis)
├── templates/
│   └── index.html       # Web interface HTML/JS/CSS
├── pyproject.toml       # Python dependencies configuration
└── README.md            # Documentation
```