"""
Password Cracking & Credential Attack Suite
============================================
Core toolkit: Dictionary Generator, Hash Extractor, Brute-Force Simulator,
Password Strength Analyzer, and Report Generator.

ETHICAL USE ONLY — Educational / Authorized Lab Environments
"""

import os
import re
import sys
import json
import math
import time
import string
import hashlib
import secrets
import logging
import itertools
import datetime
from pathlib import Path
from collections import Counter

# ─── Optional imports ────────────────────────────────────────────────────────
try:
    import passlib.hash as passlib_hash
    PASSLIB_OK = True
except ImportError:
    PASSLIB_OK = False

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
CONFIG = {
    "output_dir":   "./reports",
    "log_file":     "./reports/toolkit.log",
    "report_file":  "./reports/audit_report.json",
    "wordlist_file":"./reports/generated_wordlist.txt",
}

COMMON_PASSWORDS = [
    "password", "123456", "password1", "qwerty", "abc123", "letmein",
    "monkey", "1234567890", "iloveyou", "admin", "welcome", "login",
    "master", "hello", "shadow", "dragon", "pass", "test", "guest",
    "12345", "123456789", "password123", "admin123", "root", "toor",
    "superman", "batman", "football", "baseball", "soccer", "hockey",
    "charlie", "donald", "michael", "jessica", "ashley", "jennifer",
    "sunshine", "princess", "summer", "winter", "spring", "autumn",
    "trustno1", "whatever", "zxcvbnm", "passw0rd", "p@ssword",
]

KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
    "1qaz2wsx", "qazwsx", "1q2w3e4r", "1q2w3e", "qweasdzxc",
    "!@#$%^", "123qwe", "zaq1xsw2", "q1w2e3r4", "aaaa", "bbbb",
]

LEET_MAP = {
    'a': '@', 'e': '3', 'i': '1', 'o': '0',
    's': '$', 't': '7', 'l': '1', 'b': '8',
}

HASH_ALGORITHMS = {
    "md5":     {"id": "md5",    "label": "MD5",     "strength": "Very Weak",  "color": "red"},
    "sha1":    {"id": "sha1",   "label": "SHA-1",   "strength": "Weak",       "color": "orange"},
    "sha256":  {"id": "sha256", "label": "SHA-256", "strength": "Moderate",   "color": "yellow"},
    "sha512":  {"id": "sha512", "label": "SHA-512", "strength": "Strong",     "color": "green"},
    "ntlm":    {"id": "ntlm",   "label": "NTLM",    "strength": "Weak",       "color": "orange"},
    "bcrypt":  {"id": "bcrypt", "label": "bcrypt",  "strength": "Very Strong","color": "green"},
    "sha512crypt": {"id": "sha512crypt","label":"SHA-512-crypt","strength":"Very Strong","color":"green"},
}

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────
def setup_logging():
    os.makedirs(CONFIG["output_dir"], exist_ok=True)
    logger = logging.getLogger("PasswdToolkit")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("[%(asctime)s] [%(levelname)-8s] %(message)s",
                             datefmt="%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler(); ch.setLevel(logging.INFO); ch.setFormatter(fmt)
    fh = logging.FileHandler(CONFIG["log_file"]); fh.setLevel(logging.DEBUG); fh.setFormatter(fmt)
    logger.addHandler(ch); logger.addHandler(fh)
    return logger

logger = setup_logging()


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1 — DICTIONARY GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
class DictionaryGenerator:
    """
    Generates custom wordlists using multiple strategies:
    - Base words + mutations (leet, case, numbers, symbols)
    - Keyboard patterns
    - Common passwords
    - Name + DOB combinations
    - Hybrid combinations
    """

    def __init__(self):
        self.wordlist: list[str] = []

    def generate(self, config: dict) -> list[str]:
        """Main entry point — assembles wordlist from all enabled strategies."""
        words = set()
        logger.info("Dictionary Generator: starting wordlist generation...")

        # Strategy 1: Common passwords
        if config.get("include_common", True):
            words.update(COMMON_PASSWORDS)
            words.update(KEYBOARD_PATTERNS)
            logger.info(f"  [+] Added {len(COMMON_PASSWORDS)} common passwords")

        # Strategy 2: Custom base words
        base_words = config.get("base_words", [])
        if base_words:
            words.update(w.lower() for w in base_words)
            words.update(w.upper() for w in base_words)
            words.update(w.capitalize() for w in base_words)

        # Strategy 3: Name + DOB combos
        name = config.get("name", "")
        dob  = config.get("dob", "")
        if name:
            name_variants = self._name_variants(name, dob)
            words.update(name_variants)
            logger.info(f"  [+] Generated {len(name_variants)} name+DOB variants")

        # Strategy 4: Mutations on all words so far
        if config.get("apply_mutations", True):
            mutated = set()
            for w in list(words):
                mutated.update(self._mutate(w))
            words.update(mutated)

        # Strategy 5: Number appends
        if config.get("append_numbers", True):
            numbered = set()
            base_sample = [w for w in list(words) if len(w) <= 10][:200]
            for w in base_sample:
                for n in ["1", "12", "123", "1234", "12345", "2024", "2025",
                          "!", "@", "#", "!", "01", "99", "007", "000"]:
                    numbered.add(w + n)
                    numbered.add(n + w)
            words.update(numbered)

        # Deduplicate and filter
        self.wordlist = sorted(set(w for w in words if 4 <= len(w) <= 20))
        logger.info(f"  [+] Final wordlist size: {len(self.wordlist)} entries")
        return self.wordlist

    def _name_variants(self, name: str, dob: str = "") -> set:
        variants = set()
        parts = name.lower().split()
        first = parts[0] if parts else name.lower()
        last  = parts[-1] if len(parts) > 1 else ""

        # Basic combos
        variants.update([
            first, last, first+last, last+first,
            first.capitalize(), last.capitalize(),
            first+last+"123", first+"123", first+"1234",
        ])

        # DOB combinations
        if dob:
            dob_clean = re.sub(r"[^\d]", "", dob)
            if len(dob_clean) >= 4:
                yr = dob_clean[-4:]
                yr2 = dob_clean[-2:]
                for base in [first, last, first+last]:
                    variants.update([
                        base+yr, base+yr2, base+"@"+yr,
                        base.capitalize()+yr, yr+base, yr2+base,
                    ])
        return {v for v in variants if v}

    def _mutate(self, word: str) -> set:
        """Apply leet-speak, case variations, and prefix/suffix mutations."""
        variants = {word, word.upper(), word.capitalize()}

        # Leet speak
        leet = word
        for ch, rep in LEET_MAP.items():
            leet = leet.replace(ch, rep)
        if leet != word:
            variants.add(leet)
            variants.add(leet.capitalize())

        # Common suffixes
        for suffix in ["!", "1!", "@1", "#1", "123!", "!@#"]:
            variants.add(word + suffix)

        # Mixed case first+last char
        if len(word) >= 2:
            variants.add(word[0].upper() + word[1:])

        return variants

    def save(self, filepath: str = None) -> str:
        path = filepath or CONFIG["wordlist_file"]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.wordlist))
        logger.info(f"Wordlist saved → {path} ({len(self.wordlist)} words)")
        return path

    def stats(self) -> dict:
        lengths = [len(w) for w in self.wordlist]
        return {
            "total_words":   len(self.wordlist),
            "avg_length":    round(sum(lengths)/len(lengths), 2) if lengths else 0,
            "min_length":    min(lengths) if lengths else 0,
            "max_length":    max(lengths) if lengths else 0,
            "sample":        self.wordlist[:20],
        }


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2 — HASH EXTRACTOR / GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
class HashExtractor:
    """
    Hash extraction and generation module.
    - Hashes passwords using MD5, SHA-1, SHA-256, SHA-512, NTLM
    - Reads /etc/shadow entries (Linux)
    - Identifies hash algorithm from prefix
    - Simulation data for controlled lab demo
    """

    SHADOW_PREFIXES = {
        "$1$":   "MD5-crypt",
        "$2$":   "bcrypt",
        "$2a$":  "bcrypt",
        "$2b$":  "bcrypt",
        "$5$":   "SHA-256-crypt",
        "$6$":   "SHA-512-crypt",
        "$y$":   "yescrypt",
        "":      "DES-crypt (legacy)",
    }

    def hash_password(self, password: str, algorithm: str) -> str:
        """Hash a password with the specified algorithm."""
        pw_bytes = password.encode("utf-8")
        if algorithm == "md5":
            return hashlib.md5(pw_bytes).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(pw_bytes).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(pw_bytes).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(pw_bytes).hexdigest()
        elif algorithm == "ntlm":
            return hashlib.new("md4", password.encode("utf-16-le")).hexdigest()
        return "unsupported"

    def hash_all(self, password: str) -> dict:
        """Return hashes of a password in all supported algorithms."""
        return {algo: self.hash_password(password, algo)
                for algo in ["md5","sha1","sha256","sha512","ntlm"]}

    def identify_hash(self, hash_str: str) -> str:
        """Identify hash algorithm from format/length."""
        h = hash_str.strip()
        if h.startswith("$"):
            for prefix, name in self.SHADOW_PREFIXES.items():
                if h.startswith(prefix) and prefix:
                    return name
        length = len(h)
        if length == 32  and all(c in "0123456789abcdef" for c in h.lower()): return "MD5 or NTLM"
        if length == 40  and all(c in "0123456789abcdef" for c in h.lower()): return "SHA-1"
        if length == 64  and all(c in "0123456789abcdef" for c in h.lower()): return "SHA-256"
        if length == 128 and all(c in "0123456789abcdef" for c in h.lower()): return "SHA-512"
        return "Unknown"

    def read_shadow_file(self, filepath: str = "/etc/shadow") -> list:
        """Read and parse Linux /etc/shadow (requires root). Falls back to simulation."""
        entries = []
        try:
            with open(filepath, "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1] not in ["*", "!", "", "x"]:
                        entries.append({
                            "username":  parts[0],
                            "hash":      parts[1],
                            "algorithm": self._detect_shadow_algo(parts[1]),
                        })
            logger.info(f"Read {len(entries)} shadow entries from {filepath}")
        except PermissionError:
            logger.warning("Cannot read /etc/shadow (permission denied). Using simulation data.")
            entries = self._simulate_shadow()
        except FileNotFoundError:
            logger.warning(f"{filepath} not found. Using simulation data.")
            entries = self._simulate_shadow()
        return entries

    def _detect_shadow_algo(self, hash_str: str) -> str:
        for prefix, name in self.SHADOW_PREFIXES.items():
            if hash_str.startswith(prefix) and prefix:
                return name
        return "DES-crypt"

    def _simulate_shadow(self) -> list:
        """Realistic simulated shadow file entries for lab demo."""
        sim_passwords = [
            ("root",    "toor",         "md5"),
            ("admin",   "admin123",     "md5"),
            ("alice",   "alice2024",    "sha512"),
            ("bob",     "p@ssword1",    "sha512"),
            ("charlie", "charlie!",     "sha512"),
            ("dave",    "Qwerty123",    "sha1"),
            ("eve",     "iloveyou",     "md5"),
            ("frank",   "Fr@nk2023",    "sha256"),
            ("grace",   "grace123!",    "sha512"),
            ("henry",   "letmein",      "md5"),
        ]
        entries = []
        for user, pw, algo in sim_passwords:
            h = self.hash_password(pw, algo)
            entries.append({
                "username":       user,
                "hash":           h,
                "algorithm":      algo.upper(),
                "plaintext_demo": pw,  # only for lab simulation
                "strength":       PasswordStrengthAnalyzer().analyze(pw)["grade"],
            })
        return entries


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3 — BRUTE-FORCE SIMULATOR
# ─────────────────────────────────────────────────────────────────────────────
class BruteForceSimulator:
    """
    Simulates dictionary and brute-force cracking attempts.
    - Dictionary attack: try wordlist against hashes
    - Brute-force: generate candidates up to a given length
    - Reports cracked passwords, attempt counts, and estimated times
    """

    # Approximate MD5 hash rate (hashes/sec) on a modern CPU
    CRACK_RATES = {
        "md5":          10_000_000,
        "sha1":          7_000_000,
        "sha256":        3_000_000,
        "sha512":        1_000_000,
        "ntlm":         15_000_000,
        "bcrypt":               10,
        "sha512crypt":       5_000,
    }

    def __init__(self, hash_extractor: HashExtractor):
        self.extractor = hash_extractor

    def dictionary_attack(self, targets: list[dict], wordlist: list[str],
                          algorithm: str = "md5") -> dict:
        """
        Run a dictionary attack against a list of {username, hash} targets.
        Returns cracked entries and statistics.
        """
        cracked   = []
        failed    = []
        attempts  = 0
        start     = time.time()
        target_map = {t["hash"]: t["username"] for t in targets}

        logger.info(f"Dictionary attack: {len(wordlist)} words vs {len(targets)} hashes ({algorithm.upper()})")

        for word in wordlist:
            h = self.extractor.hash_password(word, algorithm)
            attempts += 1
            if h in target_map:
                user = target_map[h]
                cracked.append({
                    "username":   user,
                    "hash":       h,
                    "plaintext":  word,
                    "attempts":   attempts,
                    "algorithm":  algorithm.upper(),
                })
                logger.warning(f"  [CRACKED] {user}: '{word}' after {attempts} attempts")

        elapsed = time.time() - start
        for t in targets:
            if t["hash"] not in {c["hash"] for c in cracked}:
                failed.append(t["username"])

        return {
            "attack_type":     "Dictionary",
            "algorithm":       algorithm.upper(),
            "wordlist_size":   len(wordlist),
            "total_targets":   len(targets),
            "cracked_count":   len(cracked),
            "failed_count":    len(failed),
            "cracked":         cracked,
            "failed_users":    failed,
            "attempts":        attempts,
            "elapsed_seconds": round(elapsed, 4),
            "rate_per_sec":    round(attempts / elapsed) if elapsed > 0 else 0,
        }

    def brute_force_estimate(self, password: str, algorithm: str = "md5") -> dict:
        """
        Estimate brute-force cracking time for a given password.
        Does NOT actually crack — computes keyspace and divides by crack rate.
        """
        charset_size = 0
        has_lower  = any(c in string.ascii_lowercase for c in password)
        has_upper  = any(c in string.ascii_uppercase for c in password)
        has_digit  = any(c in string.digits          for c in password)
        has_symbol = any(c in string.punctuation     for c in password)

        if has_lower:  charset_size += 26
        if has_upper:  charset_size += 26
        if has_digit:  charset_size += 10
        if has_symbol: charset_size += 32

        charset_size = max(charset_size, 26)
        length       = len(password)
        keyspace     = charset_size ** length
        rate         = self.CRACK_RATES.get(algorithm, 1_000_000)

        seconds_avg  = (keyspace / 2) / rate
        seconds_max  = keyspace / rate

        return {
            "password":         password,
            "length":           length,
            "algorithm":        algorithm.upper(),
            "charset_size":     charset_size,
            "keyspace":         keyspace,
            "keyspace_display": f"{keyspace:,}",
            "crack_rate_ps":    f"{rate:,}",
            "time_avg_seconds": seconds_avg,
            "time_avg_display": self._format_time(seconds_avg),
            "time_max_display": self._format_time(seconds_max),
        }

    def simulate_incremental(self, charset: str = "lower", max_length: int = 4,
                              target_hash: str = "", algorithm: str = "md5") -> dict:
        """
        Simulate an incremental brute-force attack up to max_length.
        Returns attempts, time, and cracked result (if found).
        """
        charsets = {
            "lower":   string.ascii_lowercase,
            "upper":   string.ascii_uppercase,
            "digits":  string.digits,
            "alnum":   string.ascii_lowercase + string.digits,
            "full":    string.ascii_letters + string.digits + "!@#$%",
        }
        chars   = charsets.get(charset, string.ascii_lowercase)
        attempts= 0
        found   = None
        start   = time.time()
        cap     = 500_000  # safety cap for demo

        for length in range(1, max_length + 1):
            for candidate in itertools.product(chars, repeat=length):
                word = "".join(candidate)
                h    = self.extractor.hash_password(word, algorithm)
                attempts += 1
                if target_hash and h == target_hash:
                    found = word
                    break
                if attempts >= cap:
                    break
            if found or attempts >= cap:
                break

        elapsed = time.time() - start
        return {
            "attack_type":  "Incremental Brute-Force",
            "charset":      charset,
            "max_length":   max_length,
            "algorithm":    algorithm.upper(),
            "attempts":     attempts,
            "elapsed_sec":  round(elapsed, 4),
            "cracked":      found,
            "capped":       attempts >= cap,
        }

    def _format_time(self, seconds: float) -> str:
        if seconds < 1:       return "< 1 second"
        if seconds < 60:      return f"{seconds:.1f} seconds"
        if seconds < 3600:    return f"{seconds/60:.1f} minutes"
        if seconds < 86400:   return f"{seconds/3600:.1f} hours"
        if seconds < 2592000: return f"{seconds/86400:.1f} days"
        if seconds < 31536000:return f"{seconds/2592000:.1f} months"
        yrs = seconds / 31536000
        if yrs > 1e9:         return f"{yrs:.2e} years"
        return f"{yrs:.1f} years"


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4 — PASSWORD STRENGTH ANALYZER
# ─────────────────────────────────────────────────────────────────────────────
class PasswordStrengthAnalyzer:
    """
    Analyzes password strength based on:
    - Length, character set diversity
    - Shannon entropy
    - Common password detection
    - Keyboard pattern detection
    - Repeated character detection
    - Improvement recommendations
    """

    def analyze(self, password: str) -> dict:
        score    = 0
        issues   = []
        tips     = []
        length   = len(password)

        # ── Length scoring ──────────────────────────────────
        if length < 6:
            issues.append("Too short (< 6 characters)")
        elif length < 8:
            score += 1; issues.append("Short — recommend 12+ characters")
        elif length < 12:
            score += 2
        elif length < 16:
            score += 3
        else:
            score += 4

        # ── Character diversity ─────────────────────────────
        has_lower  = bool(re.search(r'[a-z]', password))
        has_upper  = bool(re.search(r'[A-Z]', password))
        has_digit  = bool(re.search(r'\d',    password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

        diversity = sum([has_lower, has_upper, has_digit, has_symbol])
        score += diversity

        if not has_upper:  issues.append("No uppercase letters"); tips.append("Add uppercase letters (A-Z)")
        if not has_digit:  issues.append("No digits");            tips.append("Add numbers (0-9)")
        if not has_symbol: issues.append("No special characters");tips.append("Add symbols (!@#$%^&*)")
        if not has_lower:  issues.append("No lowercase letters"); tips.append("Add lowercase letters (a-z)")

        # ── Common password check ───────────────────────────
        is_common = password.lower() in COMMON_PASSWORDS
        if is_common:
            score = max(0, score - 3)
            issues.append("Common/dictionary password — easily cracked")
            tips.append("Use a unique passphrase not found in any dictionary")

        # ── Keyboard pattern check ──────────────────────────
        is_keyboard = any(pat in password.lower() for pat in KEYBOARD_PATTERNS)
        if is_keyboard:
            score = max(0, score - 2)
            issues.append("Contains keyboard pattern (qwerty, 1234…)")
            tips.append("Avoid sequential keyboard patterns")

        # ── Repeated characters ─────────────────────────────
        if re.search(r'(.)\1{2,}', password):
            score = max(0, score - 1)
            issues.append("Contains repeated characters (aaa, 111…)")
            tips.append("Avoid repeating the same character 3+ times")

        # ── Entropy calculation ─────────────────────────────
        charset = 0
        if has_lower:  charset += 26
        if has_upper:  charset += 26
        if has_digit:  charset += 10
        if has_symbol: charset += 32
        charset  = max(charset, 26)
        entropy  = length * math.log2(charset)

        # ── Shannon entropy ─────────────────────────────────
        freq = Counter(password)
        shannon = -sum((c/length)*math.log2(c/length) for c in freq.values()) if length > 0 else 0

        # ── Clamp and grade ─────────────────────────────────
        score = max(0, min(score, 10))

        if score <= 2:   grade, color = "Very Weak",   "red"
        elif score <= 4: grade, color = "Weak",         "orange"
        elif score <= 6: grade, color = "Moderate",     "yellow"
        elif score <= 8: grade, color = "Strong",       "green"
        else:            grade, color = "Very Strong",  "green"

        if not tips:
            tips.append("Password meets all complexity requirements. Consider using a passphrase for even better security.")

        return {
            "password":       password,
            "masked":         password[0] + "*" * (length-2) + password[-1] if length > 2 else "***",
            "length":         length,
            "score":          score,
            "max_score":      10,
            "grade":          grade,
            "color":          color,
            "entropy_bits":   round(entropy, 2),
            "shannon_entropy":round(shannon, 3),
            "charset_size":   charset,
            "has_lower":      has_lower,
            "has_upper":      has_upper,
            "has_digit":      has_digit,
            "has_symbol":     has_symbol,
            "is_common":      is_common,
            "is_keyboard":    is_keyboard,
            "issues":         issues,
            "tips":           tips,
        }

    def batch_analyze(self, passwords: list[str]) -> list[dict]:
        return [self.analyze(pw) for pw in passwords]

    def policy_check(self, password: str, policy: dict) -> dict:
        """Check password against an organizational policy."""
        violations = []
        if len(password) < policy.get("min_length", 8):
            violations.append(f"Too short (minimum {policy['min_length']} characters required)")
        if policy.get("require_upper") and not re.search(r'[A-Z]', password):
            violations.append("Missing uppercase letter")
        if policy.get("require_digit") and not re.search(r'\d', password):
            violations.append("Missing digit")
        if policy.get("require_symbol") and not re.search(r'[^a-zA-Z0-9]', password):
            violations.append("Missing special character")
        if policy.get("block_common") and password.lower() in COMMON_PASSWORDS:
            violations.append("Password in common password list")
        return {
            "password":    password,
            "policy":      policy,
            "passed":      len(violations) == 0,
            "violations":  violations,
        }


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5 — REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
class ReportGenerator:
    """
    Generates a structured JSON audit report summarising all module results.
    """

    def generate(self, results: dict) -> dict:
        ts = datetime.datetime.now().isoformat()

        # Count severity distribution
        strength_results = results.get("strength_results", [])
        grades = Counter(r["grade"] for r in strength_results)
        total  = len(strength_results)
        weak   = grades.get("Very Weak",0) + grades.get("Weak",0)

        crack_results = results.get("crack_results", {})
        cracked_count = crack_results.get("cracked_count", 0)
        total_targets = crack_results.get("total_targets", 0)

        report = {
            "report_metadata": {
                "title":        "Password Security Audit Report",
                "generated_at": ts,
                "tool":         "Password Cracking & Credential Attack Suite v1.0",
                "mode":         "Ethical Lab / Simulation",
            },
            "executive_summary": {
                "passwords_analyzed":      total,
                "weak_or_very_weak":       weak,
                "weak_percentage":         round((weak/total)*100, 1) if total else 0,
                "hashes_targeted":         total_targets,
                "hashes_cracked":          cracked_count,
                "crack_success_rate":      round((cracked_count/total_targets)*100,1) if total_targets else 0,
                "wordlist_size":           results.get("wordlist_size", 0),
                "overall_risk":            "CRITICAL" if cracked_count > total_targets*0.5 else
                                           "HIGH"     if cracked_count > 0 else "LOW",
                "grade_distribution":      dict(grades),
            },
            "dictionary_generator":        results.get("dict_stats", {}),
            "hash_extraction":             results.get("shadow_entries", []),
            "brute_force_simulation":      crack_results,
            "brute_force_estimates":       results.get("bf_estimates", []),
            "strength_analysis":           strength_results,
            "policy_violations":           results.get("policy_violations", []),
            "recommendations": [
                "Enforce minimum 12-character passwords across all accounts",
                "Require uppercase, lowercase, digit, and symbol in every password",
                "Deploy a password manager to avoid password reuse",
                "Implement account lockout after 5 failed attempts (NIST SP 800-63B)",
                "Store passwords using bcrypt, scrypt, or Argon2 — never MD5 or SHA-1",
                "Enable Multi-Factor Authentication (MFA) on all accounts",
                "Run quarterly password audits to detect weak or reused passwords",
                "Block commonly known passwords using a deny-list at registration",
                "Educate users on phishing and credential stuffing risks",
                "Monitor authentication logs for brute-force patterns",
            ],
        }

        path = CONFIG["report_file"]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Audit report saved → {path}")
        return report


# ─────────────────────────────────────────────────────────────────────────────
# FULL PIPELINE RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def run_full_pipeline(config: dict = None) -> dict:
    """Execute all 5 modules and return consolidated results."""
    cfg = config or {}
    logger.info("=" * 60)
    logger.info("  PASSWORD CRACKING & CREDENTIAL ATTACK SUITE")
    logger.info("  ETHICAL SIMULATION MODE")
    logger.info("=" * 60)

    # ── Module 1: Dictionary Generator ──────────────────────
    logger.info("\n[MODULE 1] Dictionary Generator")
    gen = DictionaryGenerator()
    wordlist = gen.generate({
        "include_common":   True,
        "apply_mutations":  True,
        "append_numbers":   True,
        "name":             cfg.get("name", "alice"),
        "dob":              cfg.get("dob",  "19900115"),
        "base_words":       cfg.get("base_words", ["password","company","secure"]),
    })
    gen.save()
    dict_stats = gen.stats()

    # ── Module 2: Hash Extractor ─────────────────────────────
    logger.info("\n[MODULE 2] Hash Extractor")
    extractor = HashExtractor()
    shadow_entries = extractor.read_shadow_file()

    # ── Module 3: Brute-Force Simulator ──────────────────────
    logger.info("\n[MODULE 3] Brute-Force Simulator")
    sim = BruteForceSimulator(extractor)

    # Dictionary attack on shadow entries
    targets = [{"username": e["username"], "hash": e["hash"]}
               for e in shadow_entries]
    crack_results = sim.dictionary_attack(targets, wordlist[:2000], algorithm="md5")

    # Brute-force estimates for various passwords
    test_passwords = [
        ("abc",       "md5"),
        ("password",  "md5"),
        ("Pass1!",    "sha256"),
        ("Tr0ub4dor!", "sha512"),
        ("P@ssw0rd123!","sha512"),
        ("xK#9mL2$qW","bcrypt"),
    ]
    bf_estimates = [sim.brute_force_estimate(pw, algo) for pw, algo in test_passwords]

    # ── Module 4: Strength Analyzer ──────────────────────────
    logger.info("\n[MODULE 4] Password Strength Analyzer")
    analyzer = PasswordStrengthAnalyzer()
    sample_passwords = [
        "abc", "password", "123456", "qwerty123",
        "Alice2024!", "Secure#Pass99", "P@ssw0rd",
        "Tr0ub4dor&3", "correct-horse-battery-staple",
        "xK#9mL2$qWnR!8", "admin", "iloveyou",
    ]
    strength_results = analyzer.batch_analyze(sample_passwords)

    # Policy check
    policy = {
        "min_length":    12,
        "require_upper": True,
        "require_digit": True,
        "require_symbol":True,
        "block_common":  True,
    }
    policy_violations = [
        analyzer.policy_check(pw, policy)
        for pw in sample_passwords
        if not analyzer.policy_check(pw, policy)["passed"]
    ]

    # ── Module 5: Report Generator ────────────────────────────
    logger.info("\n[MODULE 5] Report Generator")
    reporter = ReportGenerator()
    report = reporter.generate({
        "dict_stats":       dict_stats,
        "shadow_entries":   shadow_entries,
        "crack_results":    crack_results,
        "bf_estimates":     bf_estimates,
        "strength_results": strength_results,
        "policy_violations":policy_violations,
        "wordlist_size":    len(wordlist),
    })

    logger.info("\n✅ Full pipeline complete.")
    return report


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Password Cracking & Credential Attack Suite")
    parser.add_argument("--name",  default="alice",    help="Name for wordlist generation")
    parser.add_argument("--dob",   default="19900115", help="Date of birth (YYYYMMDD)")
    parser.add_argument("--words", nargs="*",          help="Additional base words for wordlist")
    parser.add_argument("--output",default="./reports",help="Output directory")
    args = parser.parse_args()

    CONFIG["output_dir"]  = args.output
    CONFIG["log_file"]    = os.path.join(args.output, "toolkit.log")
    CONFIG["report_file"] = os.path.join(args.output, "audit_report.json")

    report = run_full_pipeline({
        "name":       args.name,
        "dob":        args.dob,
        "base_words": args.words or [],
    })

    summary = report["executive_summary"]
    print(f"\n{'═'*55}")
    print("  AUDIT SUMMARY")
    print(f"{'═'*55}")
    print(f"  Passwords Analyzed  : {summary['passwords_analyzed']}")
    print(f"  Weak / Very Weak    : {summary['weak_or_very_weak']} ({summary['weak_percentage']}%)")
    print(f"  Hashes Targeted     : {summary['hashes_targeted']}")
    print(f"  Hashes Cracked      : {summary['hashes_cracked']} ({summary['crack_success_rate']}%)")
    print(f"  Wordlist Size       : {summary['wordlist_size']:,} words")
    print(f"  Overall Risk        : {summary['overall_risk']}")
    print(f"{'═'*55}")
    print(f"  Full report → {CONFIG['report_file']}")