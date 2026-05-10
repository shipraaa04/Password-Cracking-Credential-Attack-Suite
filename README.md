# 🔐 Password Cracking & Credential Attack Suite

> **Ethical simulation toolkit** — Password policy testing, credential security assessment, and authentication hardening for authorized lab environments.



## ⚠️ Ethical Use Notice

This toolkit is developed **exclusively** for:
- Defensive security education and authorized lab environments
- Password policy auditing on systems you own or have written permission to test
- Academic cybersecurity coursework and research

**Unauthorized use against real systems is illegal and unethical.**

---

## What It Does

Five fully integrated modules in one toolkit:

| Module | Class | What It Does |
|--------|-------|--------------|
| 1 | `DictionaryGenerator` | Generates wordlists — leet-speak, name+DOB, keyboard patterns, mutations |
| 2 | `HashExtractor` | Hashes passwords (MD5/SHA-1/SHA-256/SHA-512/NTLM), reads /etc/shadow, identifies hash types |
| 3 | `BruteForceSimulator` | Dictionary attacks, incremental brute-force, time-to-crack estimation |
| 4 | `PasswordStrengthAnalyzer` | Entropy, complexity, common-password detection, policy checking |
| 5 | `ReportGenerator` | Structured JSON audit report with recommendations |

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run Streamlit dashboard
streamlit run app.py

# Run CLI toolkit
python toolkit.py --name alice --dob 19900115

# With custom words
python toolkit.py --name alice --dob 19900115 --words company office secure
```

---

## Dashboard Tabs

| Tab | Contents |
|-----|----------|
| 📚 Dictionary Generator | Configure and preview wordlists with mutation strategy table |
| 🔒 Hash Extractor | Hash passwords, identify hashes, view simulated shadow entries |
| 💥 Brute-Force Sim | Dictionary attack results, time-to-crack estimator, custom attack |
| 🛡️ Strength Analyzer | Live strength meter, policy checker, batch analysis, entropy table |
| 📊 Analytics | Grade distribution charts, issue frequency, algorithm vulnerability table |
| 📄 Audit Report | Full JSON report download, recommendations, policy violations |

---

## Supported Hash Algorithms

| Algorithm | Crack Speed | Salted | Recommended |
|-----------|-------------|--------|-------------|
| MD5 | ~10M/s | No | ❌ Broken |
| SHA-1 | ~7M/s | No | ❌ Deprecated |
| NTLM | ~15M/s | No | ❌ Legacy |
| SHA-256 | ~3M/s | No | ⚠️ Acceptable |
| SHA-512 | ~1M/s | No | ⚠️ Acceptable |
| bcrypt | ~10/s | Yes | ✅ Recommended |
| Argon2 | ~1/s | Yes | ✅ Best Practice |

---

## CLI Options

```
python toolkit.py --name <name> --dob <YYYYMMDD> --words [word1 word2 ...] --output ./reports
```

---

## Project Structure

```
.
├── app.py              ← Streamlit dashboard (6 tabs)
├── toolkit.py          ← Core engine (5 modules, ~500 lines)
├── requirements.txt    ← Python dependencies
├── runtime.txt         ← Python 3.11
├── README.md           ← This file
├── CHANGELOG.md        ← Version history
├── CONTRIBUTING.md     ← Contribution guidelines
├── .gitignore          ← Excludes reports/, __pycache__, logs
└── reports/ (generated)
    ├── audit_report.json
    ├── generated_wordlist.txt
    └── toolkit.log
```

---
