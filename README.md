# HTTP Brute Force Lab - Educational Security Framework

**Python 3.x** | **Educational License** | [View License](LICENSE)

⚠️ **For Educational Purposes and Authorized Security Research Only**

---

## 📌 Description

HTTP Brute Force Lab is an educational framework designed to demonstrate HTTP brute force attack concepts in cybersecurity training and research in controlled environments.

### Purpose

This toolkit helps security professionals, students, and researchers understand:
- HTTP form-based authentication attacks
- Credential testing methodologies
- Response analysis techniques
- Detection of successful authentication
- Security defensive measures

---

## 🎓 Educational Use Cases

**Appropriate for:**
- ✅ University cybersecurity courses
- ✅ Professional security certifications (CEH, OSCP, GPEN)
- ✅ Corporate security awareness training
- ✅ Authorized penetration assessments
- ✅ Red team exercises in isolated environments
- ✅ Academic security research

---

## 🛠 Features

### http_form_force.py - Brute Force Tool
- Sequential credential testing (no multithreading)
- Automatic form detection and parsing
- Smart credential prioritization
- Response analysis for success detection
- CSRF token handling
- User-Agent rotation for evasion
- Auto-throttling on rate limit detection
- Detailed logging and statistics

### server.py - Lab Login Server
- Simple Flask-based login server
- CSRF protection
- Configurable via environment variables
- Perfect for practice in isolated labs

---

## 📋 Requirements

- Python 3.x
- Dependencies (installed automatically):
  - requests
  - beautifulsoup4
  - Flask (for lab server only)

---

## 🚀 Installation

```bash
git clone https://github.com/dereeqw/http_form_force
cd http_form_force

# Install dependencies
pip install -r requirements.txt
```

---

## 📚 Usage

### Start the Lab Server

```bash
# Using default credentials (admin:changeme123)
python3 Server.py

# Using custom credentials
export LAB_USERNAME="testuser"
export LAB_PASSWORD="testpass123"
python3 Server.py
```

The server will run on `http://127.0.0.1:8080`

### Run the Brute Force Tool

**Basic attack:**
```bash
python3 http_form_force.py -u http://127.0.0.1:8080/ users.txt passwords.txt
```

**With delay (stealth mode):**
```bash
python3 http_form_force.py -u http://127.0.0.1:8080/ users.txt passwords.txt --delay 2.0
```

**Using combo file (user:pass format):**
```bash
python3 http_form_force.py -u http://127.0.0.1:8080/ combos.txt --combo
```

**With custom configuration:**
```bash
python3 http_form_force.py -u http://127.0.0.1:8080/ users.txt passwords.txt --config custom.json
```

**Verbose output:**
```bash
python3 http_form_force.py -u http://127.0.0.1:8080/ users.txt passwords.txt -v
```

---

## 📁 File Formats

### Users/Passwords Files
Plain text files with one entry per line:
```
admin
root
user
test
```

### Combo File
Format: `username:password`
```
admin:admin
root:toor
user:password123
```

---

## ⚙️ Configuration

The tool can be customized using a JSON configuration file. See `custom.json` for all available options:

- Delays and timing
- User-Agent rotation
- Success/fail detection keywords
- Auto-throttling settings
- Form field detection patterns

---

## 📊 Results

Results are saved in the `./results` directory:
- **credentials_*.json**: Found valid credentials
- **statistics_*.json**: Attack statistics and metrics
- **Individual credential files**: Saved immediately when found

---

## 🔒 Legal & Ethical Guidelines

### ⚠️ CRITICAL WARNING

This tool is provided **EXCLUSIVELY** for:
- Educational purposes in controlled environments
- Authorized security testing with written permission
- Laboratory practice on systems you own

### 🚫 NEVER USE THIS TOOL FOR:
- Unauthorized access attempts
- Attacking systems without explicit written permission
- Any illegal, unethical, or malicious activities
- Production systems without proper authorization

### ⚖️ Legal Responsibility

- Using this tool against systems you don't own or have permission to test is **ILLEGAL**
- You are **SOLELY RESPONSIBLE** for ensuring compliance with all applicable laws
- Unauthorized use may result in criminal prosecution
- Always obtain written authorization before testing

---

## 🛡️ Defensive Measures

This tool can help organizations understand and implement:
- Rate limiting mechanisms
- Account lockout policies
- CAPTCHA implementation
- Failed login monitoring
- IP-based blocking
- Multi-factor authentication

---

## 🤝 Contributing

Contributions for educational improvements are welcome. Please ensure all contributions:
- Maintain educational focus
- Include proper warnings
- Follow ethical guidelines
- Improve learning outcomes

---

## 📜 License

This project is licensed under the Educational Security Research License.  
See [LICENSE](LICENSE) file for full details.

---

## ⚠️ Disclaimer

THE AUTHORS ARE NOT RESPONSIBLE FOR:
- Misuse of this software
- Legal consequences from unauthorized use
- Damages, losses, or claims arising from implementation
- Violations of local, state, federal, or international laws

By using this software, you accept full responsibility for your actions.

---
