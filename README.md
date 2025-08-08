# Security Strike Sentinel

![ZAP Scan](https://github.com/Toraaaamizu/securitystrikesentinel/actions/workflows/zap-scan.yml/badge.svg)

Security Strike Sentinel is an advanced security testing automation toolkit built around the OWASP ZAP Proxy. It performs automated scans, generates rich HTML/CSV reports, and supports delta analysis, CI/CD integration, and authentication-based testing.

---

## 🚀 Features

- ✅ CLI-powered ZAP vulnerability scanning
- 📊 HTML & CSV reporting with charts, risk summaries, and duration
- 🔐 Authenticated scanning (form/manual/http login)
- 🔁 Delta reporting support (compare with previous run)
- ⏱️ Dynamic timeout estimation based on target RTT
- 🛠️ Scan policy selection and context support
- 🧪 JUnit-ready tests (optional)
- ⚙️ GitHub Actions and CI/CD friendly

---

## 📦 Installation

```
git clone https://github.com/Toraaaamizu/securitystrikesentinel.git
cd securitystrikesentinel
./gradlew fatJar
```

---

## 🧪 Usage

Run a ZAP scan against a target:

```bash
java -jar build/libs/security-strike-sentinel-all.jar \
  --zapscan http://testphp.vulnweb.com \
  --context my-context \
  --policy "Default Policy" \
  --ci-mode \
  --delta \
  --html-report
```

### 🧩 Authenticated Scanning

```bash
--auth-username admin \
--auth-password password123 \
--auth-method form \
--auth-login-url http://testsite/login \
--auth-username-field username \
--auth-password-field password \
--auth-logged-in-indicator "Logout"
```

### 📄 CLI Flags

```bash
--zapscan              Run ZAP scan on target
--quick                Use quick mode (passive only)
--html-report          Generate HTML report
--csv-report           Generate CSV report
--context              Context name to use
--policy               Scan policy name to use
--ci-mode              Fail build if high risk found
--delta                Enable delta report
--auth-*               Authentication settings
--spider-timeout       Spider timeout override
--ascan-timeout        Active scan timeout override
```

---

## 🖼️ Sample Reports

[Report Overview](docs/screenshots/overview.png)
---

## 🛠️ Development & Build

Requires:
- Java 11+
- Gradle 7+
- OWASP ZAP (running as proxy with API key)

### Build
```bash
./gradlew fatJar
```

### Test
```bash
./gradlew test
```

---

## 📄 License

```
Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/
```

See [LICENSE](LICENSE) for full text.

---

## 🤝 Contributions

PRs and issues are welcome! Star ⭐ the project to support.

---

## 👥 Authors

- [@Toraaaamizu](https://github.com/Toraaaamizu)

---

## 📌 Notes

- Ensure ZAP is running locally (`http://localhost:8080`) with API key enabled.
- HTML & CSV reports are stored in `reports/`
- Delta comparison requires previous report snapshot.
