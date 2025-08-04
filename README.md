
# 🛡️ Security Strike Sentinel

![Build](https://img.shields.io/github/actions/workflow/status/YOUR_ORG/security-strike-sentinel/ci.yml?branch=main)
![Java](https://img.shields.io/badge/java-11%2B-blue)
![License](https://img.shields.io/github/license/YOUR_ORG/security-strike-sentinel)

> Automated OWASP ZAP-powered security scanner with rich reporting, authentication support, CI integration, and delta tracking.

---

## ✨ Features

- ✅ **Automated Security Scanning** (powered by OWASP ZAP)
- 🔐 **Authentication Support** (form/manual/http with login context)
- 📊 **HTML + CSV Reports** with severity breakdowns and charts
- 🧪 **CI/CD Integration** with exit status for vulnerabilities
- 🧠 **Delta Reporting** (compare with previous scan)
- 🛠️ **Custom Scan Policy** & configurable timeouts
- 🖥️ **Simple CLI Interface**

---

## 📦 Requirements

- Java 11 or higher
- OWASP ZAP installed and running on `localhost:8080`
- API key enabled in ZAP (configure it in `ZapScanner.java` or `~/.ZAP/config.xml`)

---

## 🚀 Getting Started

### 1. Clone & Build
```bash
git clone https://github.com/YOUR_ORG/security-strike-sentinel.git
cd security-strike-sentinel
mvn clean install
```

### 2. Start ZAP in daemon/API mode
```bash
zap.sh -daemon -port 8080 -config api.key=1utjr8dcvt4521ujk7d62md5l9
```

### 3. Run a Basic Scan
```bash
java -jar target/security-strike-sentinel.jar --zapscan http://testphp.vulnweb.com --html-report
```

---

## 🛠️ CLI Usage

### 🔍 Basic Scan
```bash
--zapscan <URL>          Run a ZAP scan on the given URL
--quick                  Passive-only scan (faster, non-invasive)
--policy <name>          Use custom ZAP scan policy
```

### 🧾 Report Options
```bash
--html-report            Generate detailed HTML report (with charts)
--csv-report             Generate CSV version of scan results
--delta                  Enable delta reporting (compare previous scan)
```

### 🧪 CI Mode
```bash
--ci                     Fail with non-zero exit code on High vulnerabilities
```

### 🔐 Authentication Options
```bash
--auth-method <type>             (form, manual, http)
--auth-username <user>
--auth-password <pass>
--auth-login-url <url>
--auth-username-field <field>
--auth-password-field <field>
--auth-logged-in-indicator <regex>
--auth-logout-indicator <regex>
--auth-exclude <regex>
```

### 🕐 Timeout Options
```bash
--spider-timeout <seconds>       Override spider scan timeout
--ascan-timeout <seconds>        Override active scan timeout
```

---

## 🧪 Example CLI Commands

### 🔹 Quick Authenticated Scan
```bash
java -jar target/security-strike-sentinel.jar   --zapscan http://zero.webappsecurity.com   --quick --html-report --csv-report   --auth-method form   --auth-username user --auth-password pass   --auth-login-url http://zero.webappsecurity.com/login.html   --auth-username-field user_login   --auth-password-field user_password   --auth-logged-in-indicator "Logout"
```

### 🔸 Full CI Scan with Delta
```bash
java -jar target/security-strike-sentinel.jar   --zapscan http://testphp.vulnweb.com   --ci --html-report --delta
```

---

## 📊 Sample Report

### 📈 HTML Report (with charts)

[Report Overview](docs/screenshots/overview.png)

### 📉 CSV Output

```
Risk,Name,URL
High,Cookie No HttpOnly Flag,http://testphp.vulnweb.com/
Medium,X-Content-Type-Options Header Missing,http://testphp.vulnweb.com/
```

---

## 🧩 Project Structure

```
├── src/main/java
│   ├── cli/                 ← CLI Parser
│   ├── scanners/zap/        ← ZapScanner Logic
│   ├── auth/                ← Authentication Context Manager
│   └── reports/             ← HTML & CSV Generators
├── reports/                 ← Generated Reports (.json, .html, .csv)
└── README.md
```

---

## 🔄 CI/CD Integration

### ✅ GitHub Actions
Include this in `.github/workflows/ci.yml`:
```yaml
- name: Run Security Strike Sentinel
  run: java -jar target/security-strike-sentinel.jar --zapscan http://yourapp.com --ci --html-report
```

### 🧪 GitLab CI
```yaml
security_scan:
  script:
    - java -jar target/security-strike-sentinel.jar --zapscan http://yourapp.com --ci --html-report
```

---

## ✅ License

[MIT](LICENSE)

---

## 🙋 FAQ

**Q:** Does this require the ZAP desktop GUI?  
**A:** No, run ZAP in headless/daemon mode (`-daemon`) and use the API.

**Q:** What happens if ZAP is not running?  
**A:** The tool will fail gracefully with a message and exit.

**Q:** Can I customize the HTML report layout?  
**A:** You can extend `HtmlReportGenerator.java` or customize the embedded Chart.js logic.

---

## 🔗 References

- [OWASP ZAP API Docs](https://www.zaproxy.org/docs/api/)
- [OWASP ZAP Project](https://www.zaproxy.org/)
