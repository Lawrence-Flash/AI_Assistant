# AI Assistant for Network Scanning

This is a simple web application built with Flask that allows users to perform network scans using Nmap. The application provides a user-friendly interface to initiate scans, view scan results, and check the availability of Nmap on the system.

---

## Features

- **Network Scanning**: Perform network scans using Nmap by providing a target IP address or domain.
- **Scan History**: View the history of all scans performed, including detailed results.
- **Nmap Availability Check**: Verify if Nmap is installed and available on the system.
- **Secure Application**: Uses Flask-Talisman to enforce HTTPS and secure headers.
- **Database Integration**: Stores scan results in a database using SQLAlchemy.

---

## Prerequisites

- Python 3.7 or higher
- Nmap installed on the system
- Flask and required Python libraries (see `requirements.txt`)

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd AI_Assistant

# Project Structure
AI_Assistant/
├── app.py               # Main application file
├── models.py            # Database models (e.g., ScanResult)
├── utils.py             # Utility functions (e.g., run_nmap_scan, is_valid_target)
├── templates/           # HTML templates for rendering pages
├── static/              # Static files (CSS, JS, images)
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation

# Security
Here’s a sample `README.md` file for your project:

```markdown
# AI Assistant for Network Scanning

This is a simple web application built with Flask that allows users to perform network scans using Nmap. The application provides a user-friendly interface to initiate scans, view scan results, and check the availability of Nmap on the system.

---

## Features

- **Network Scanning**: Perform network scans using Nmap by providing a target IP address or domain.
- **Scan History**: View the history of all scans performed, including detailed results.
- **Nmap Availability Check**: Verify if Nmap is installed and available on the system.
- **Secure Application**: Uses Flask-Talisman to enforce HTTPS and secure headers.
- **Database Integration**: Stores scan results in a database using SQLAlchemy.

---

## Prerequisites

- Python 3.7 or higher
- Nmap installed on the system
- Flask and required Python libraries (see `requirements.txt`)

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd AI_Assistant
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Environment Variables**:
   - Create a `.env` file or export the following variables:
     ```bash
     export FLASK_APP=app.py
     export FLASK_ENV=development
     export SESSION_SECRET=your_secret_key
     export DATABASE_URL=sqlite:///cybersecurity.db
     ```

---

## Usage

1. **Run the Application**:
   ```bash
   flask run
   ```
   Alternatively:
   ```bash
   python app.py
   ```

2. **Access the Application**:
   Open your browser and navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## Project Structure

```
AI_Assistant/
├── app.py               # Main application file
├── models.py            # Database models (e.g., ScanResult)
├── utils.py             # Utility functions (e.g., run_nmap_scan, is_valid_target)
├── templates/           # HTML templates for rendering pages
├── static/              # Static files (CSS, JS, images)
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation
```

---

## Endpoints

### `/`
- **Method**: `GET`
- **Description**: Renders the main page of the application.

### `/scan`
- **Method**: `POST`
- **Description**: Accepts a target IP or domain and performs a network scan.

### `/scan/<int:scan_id>`
- **Method**: `GET`
- **Description**: Displays detailed results of a specific scan.

### `/history`
- **Method**: `GET`
- **Description**: Displays the history of all scans.

### `/check_nmap`
- **Method**: `GET`
- **Description**: Checks if Nmap is installed and available on the system.

---

## Security

- **Flask-Talisman**: Enforces HTTPS and secure headers.
- **Input Validation**: Ensures valid IP addresses or domain names are provided for scans.
- **Environment Variables**: Sensitive configurations like `SESSION_SECRET` and `DATABASE_URL` are managed via environment variables.

---

## Troubleshooting

- **Nmap Not Found**: Ensure Nmap is installed and accessible in your system's PATH.
- **Database Issues**: Check if the `DATABASE_URL` environment variable is set correctly.
- **Permission Errors**: Run the application with appropriate permissions or use a virtual environment.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Acknowledgments

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
- [Nmap](https://nmap.org/) - Network scanning tool
```

This `README.md` provides a comprehensive overview of your project, including setup instructions, usage, and key features. Let me know if you'd like to customize it further!This `README.md` provides a comprehensive overview of your project, including setup instructions, usage, and key features. Let me know if you'd like to customize it further!