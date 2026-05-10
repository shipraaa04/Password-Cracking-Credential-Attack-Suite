"""
Password Cracking & Credential Attack Suite — app.py
Streamlit Dashboard | ETHICAL USE ONLY | Authorized Lab Environments
"""
import os, sys, json, time, math, string, hashlib, itertools, datetime, re
from collections import Counter
import streamlit as st
import pandas as pd

st.set_page_config(page_title="Password Attack Suite", page_icon="🔐",
                   layout="wide", initial_sidebar_state="expanded")

sys.path.insert(0, os.path.dirname(__file__))
from toolkit import (DictionaryGenerator, HashExtractor, BruteForceSimulator,
                     PasswordStrengthAnalyzer, ReportGenerator, run_full_pipeline,
                     COMMON_PASSWORDS, KEYBOARD_PATTERNS, CONFIG)

# ─── CSS ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Rajdhani:wght@400;600;700&display=swap');
*, *::before, *::after { box-sizing: border-box; }
html, body, [data-testid="stAppViewContainer"] { background:#0a0e0a !important; font-family:'JetBrains Mono',monospace !important; }
[data-testid="stSidebar"] { background:#0d120d !important; border-right:1px solid #1a2e1a !important; }
[data-testid="stSidebar"] * { color:#7dbf7d !important; }
[data-testid="stSidebar"] label { color:#4a8a4a !important; font-size:11px !important; }
h1,h2,h3,h4 { font-family:'Rajdhani',sans-serif !important; letter-spacing:2px !important; }
h1 { color:#00ff41 !important; text-shadow:0 0 20px #00ff4144; }
h2 { color:#39d353 !important; }
h3 { color:#7dbf7d !important; }
p, li, .stMarkdown { color:#8aad8a !important; font-size:13px !important; }
[data-testid="metric-container"] {
  background:#0d170d !important; border:1px solid #1e3a1e !important;
  border-top:2px solid #00ff41 !important; border-radius:4px !important; padding:16px !important;
}
[data-testid="metric-container"] label { color:#4a8a4a !important; font-size:10px !important; letter-spacing:2px !important; text-transform:uppercase !important; }
[data-testid="stMetricValue"] { color:#00ff41 !important; font-size:1.8rem !important; font-weight:700 !important; font-family:'JetBrains Mono',monospace !important; }
[data-testid="stTabs"] button { font-family:'JetBrains Mono',monospace !important; color:#4a8a4a !important; border:none !important; font-size:12px !important; letter-spacing:1px !important; padding:10px 18px !important; }
[data-testid="stTabs"] button[aria-selected="true"] { color:#00ff41 !important; border-bottom:2px solid #00ff41 !important; background:#0d170d !important; }
.stTextInput input, .stSelectbox select { background:#0d170d !important; color:#00ff41 !important; border:1px solid #1e3a1e !important; border-radius:4px !important; font-family:'JetBrains Mono',monospace !important; font-size:13px !important; }
.stTextInput input:focus { border-color:#00ff41 !important; box-shadow:0 0 8px #00ff4122 !important; }
.stButton > button { background:transparent !important; color:#00ff41 !important; border:1px solid #00ff41 !important; border-radius:3px !important; font-family:'JetBrains Mono',monospace !important; font-size:12px !important; letter-spacing:2px !important; padding:10px 24px !important; transition:all .2s !important; }
.stButton > button:hover { background:#00ff4115 !important; box-shadow:0 0 12px #00ff4133 !important; }
code, pre { background:#0d170d !important; color:#00ff41 !important; border:1px solid #1e3a1e !important; border-radius:4px !important; font-family:'JetBrains Mono',monospace !important; font-size:12px !important; }
[data-testid="stDataFrame"] { border:1px solid #1e3a1e !important; border-radius:4px !important; }
hr { border-color:#1e3a1e !important; }
.stProgress > div > div { background:#00ff41 !important; }
.abox { background:#0d170d; border-left:3px solid #00ff41; padding:12px 16px; margin:6px 0; border-radius:0 4px 4px 0; font-family:'JetBrains Mono',monospace; font-size:12px; color:#8aad8a; }
.abox.crit { border-left-color:#ff3838; }
.abox.warn { border-left-color:#ffaa00; }
.abox.info { border-left-color:#4488ff; }
.abox.good { border-left-color:#00ff41; }
.sec-hdr { color:#00ff41; font-family:'Rajdhani',sans-serif; font-size:1.05rem; font-weight:700; letter-spacing:3px; border-bottom:1px solid #1e3a1e; padding-bottom:6px; margin:20px 0 12px; text-transform:uppercase; }
.tbox { background:#0d170d; border:1px solid #1e3a1e; border-radius:6px; padding:18px 22px; font-family:'JetBrains Mono',monospace; margin-bottom:14px; }
.tbox .tlabel { color:#4a8a4a; font-size:10px; letter-spacing:3px; text-transform:uppercase; }
.tbox .tval { color:#00ff41; font-size:1.5rem; font-weight:700; margin:4px 0; }
.tbox .tsub { color:#4a8a4a; font-size:11px; }
.wchip { display:inline-block; background:#0d170d; border:1px solid #1e3a1e; color:#7dbf7d; font-size:11px; padding:3px 9px; border-radius:2px; margin:2px; font-family:'JetBrains Mono',monospace; }
.sbar-wrap { background:#1a2e1a; border-radius:2px; height:8px; margin:6px 0; }
.sbar { height:8px; border-radius:2px; }
.risk-CRITICAL { color:#ff3838 !important; font-weight:700; }
.risk-HIGH     { color:#ffaa00 !important; font-weight:700; }
.risk-LOW      { color:#00ff41 !important; font-weight:700; }
</style>
""", unsafe_allow_html=True)

# ─── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 Attack Suite")
    st.markdown("---")
    st.markdown("### ⚙️ Pipeline Config")
    sb_name  = st.text_input("Target Name",     value="alice")
    sb_dob   = st.text_input("DOB (YYYYMMDD)",  value="19900115")
    sb_words = st.text_area("Base Words (one/line)", value="company\nsecure\nletmein", height=80)
    sb_algo  = st.selectbox("Hash Algorithm", ["md5","sha1","sha256","sha512","ntlm"])
    st.markdown("---")
    run_btn  = st.button("▶  RUN FULL PIPELINE")
    st.markdown("---")
    st.markdown('<div style="font-size:10px;color:#2a4a2a;letter-spacing:1px">⚠ ETHICAL USE ONLY<br>AUTHORIZED LAB ENVIRONMENTS</div>', unsafe_allow_html=True)

# ─── SESSION STATE ────────────────────────────────────────────────────────────
if "report" not in st.session_state or run_btn:
    with st.spinner("🔄 Running full detection pipeline…"):
        extra = [w.strip() for w in sb_words.split("\n") if w.strip()]
        rpt   = run_full_pipeline({"name":sb_name,"dob":sb_dob,"base_words":extra})
        st.session_state["report"]   = rpt
        st.session_state["algo"]     = sb_algo
        st.session_state["run_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

report   = st.session_state["report"]
algo     = st.session_state.get("algo","md5")
run_time = st.session_state.get("run_time","")
summary  = report["executive_summary"]

# ─── HEADER ───────────────────────────────────────────────────────────────────
st.markdown("# 🔐 PASSWORD CRACKING & CREDENTIAL ATTACK SUITE")
st.markdown(f'<div style="color:#4a8a4a;font-size:11px;letter-spacing:2px;margin-bottom:14px">ETHICAL SIMULATION  |  {run_time}  |  MODE: LAB</div>', unsafe_allow_html=True)

risk = summary.get("overall_risk","LOW")
risk_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(risk,"⚪")
st.markdown(f"""
<div class="tbox">
  <div class="tlabel">OVERALL SYSTEM RISK LEVEL</div>
  <div class="tval risk-{risk}">{risk_icon} {risk}</div>
  <div class="tsub">
    {summary['hashes_cracked']}/{summary['hashes_targeted']} hashes cracked ({summary['crack_success_rate']}%)
    &nbsp;·&nbsp;
    {summary['weak_or_very_weak']}/{summary['passwords_analyzed']} passwords weak or very weak
  </div>
</div>""", unsafe_allow_html=True)

c1,c2,c3,c4,c5,c6 = st.columns(6)
c1.metric("📋 Wordlist",   f"{summary['wordlist_size']:,}")
c2.metric("🔑 Analyzed",   summary['passwords_analyzed'])
c3.metric("❗ Weak",        summary['weak_or_very_weak'])
c4.metric("🎯 Targeted",   summary['hashes_targeted'])
c5.metric("💥 Cracked",    summary['hashes_cracked'])
c6.metric("📊 Crack Rate", f"{summary['crack_success_rate']}%")
st.markdown("---")

# ─── TABS ─────────────────────────────────────────────────────────────────────
t1,t2,t3,t4,t5,t6 = st.tabs([
    "📚 Dictionary Generator",
    "🔒 Hash Extractor",
    "💥 Brute-Force Sim",
    "🛡️ Strength Analyzer",
    "📊 Analytics",
    "📄 Audit Report",
])

# ══════════════════ TAB 1 — DICTIONARY ═══════════════════════════════════════
with t1:
    st.markdown('<div class="sec-hdr">📚 Dictionary Generator</div>', unsafe_allow_html=True)
    st.markdown("Generates custom wordlists using name+DOB combos, leet-speak mutations, keyboard patterns, and common password variants.")

    col_l, col_r = st.columns(2)
    with col_l:
        st.markdown("#### ⚙️ Generator Settings")
        g_name  = st.text_input("Name",         value=sb_name,   key="g_name")
        g_dob   = st.text_input("DOB",          value=sb_dob,    key="g_dob")
        g_base  = st.text_area("Base Words",    value="password\ncompany\nletmein", height=80, key="g_base")
        g_com   = st.checkbox("Include common passwords",     value=True, key="g_com")
        g_mut   = st.checkbox("Apply leet-speak mutations",   value=True, key="g_mut")
        g_num   = st.checkbox("Append numbers/symbols",       value=True, key="g_num")

        if st.button("🔄 GENERATE WORDLIST", key="gen_btn"):
            extra2 = [w.strip() for w in g_base.split("\n") if w.strip()]
            gen    = DictionaryGenerator()
            wl     = gen.generate({"include_common":g_com,"apply_mutations":g_mut,
                                   "append_numbers":g_num,"name":g_name,"dob":g_dob,"base_words":extra2})
            gen.save()
            st.session_state["custom_wl"] = wl
            st.success(f"✅ Generated {len(wl):,} words → reports/generated_wordlist.txt")

    with col_r:
        st.markdown("#### 📋 Wordlist Preview")
        wl_data = st.session_state.get("custom_wl") or report["dictionary_generator"].get("sample",[])
        if wl_data:
            chips = "".join(f'<span class="wchip">{w}</span>' for w in wl_data[:80])
            st.markdown(chips, unsafe_allow_html=True)
            total_wl = len(st.session_state.get("custom_wl",[])) or report["dictionary_generator"].get("total_words",0)
            st.markdown(f'<div style="color:#4a8a4a;font-size:11px;margin-top:8px">Showing first 80 of {total_wl:,} total words</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 📐 Mutation Strategies")
    df_mut = pd.DataFrame([
        ("Leet-speak",       "a→@  e→3  i→1  o→0  s→$  t→7  l→1  b→8",    "Bypasses simple blocklists"),
        ("Case Variation",   "password → Password → PASSWORD → pAsSwOrD",    "Evades case-sensitive checks"),
        ("Number Append",    "password → password1 → password123 → 2024",    "Most common real-world pattern"),
        ("Symbol Append",    "password → password! → password!@#",           "Satisfies symbol requirements"),
        ("Name + DOB",       "alice → alice1990 → Alice90 → alice@1990",     "Personalised password pattern"),
        ("Keyboard Walk",    "qwerty  asdfgh  1q2w3e4r  zxcvbn",             "Sequential keyboard shortcuts"),
        ("Prefix/Suffix",    "01password  007password  password007",          "Common padding technique"),
    ], columns=["Strategy","Example","Why It Works"])
    st.dataframe(df_mut, use_container_width=True, hide_index=True)

# ══════════════════ TAB 2 — HASH EXTRACTOR ═══════════════════════════════════
with t2:
    st.markdown('<div class="sec-hdr">🔒 Hash Extractor</div>', unsafe_allow_html=True)
    col_l, col_r = st.columns(2)

    with col_l:
        st.markdown("#### 🔑 Hash a Plaintext Password")
        h_pw = st.text_input("Enter password", type="password", key="h_pw")
        if h_pw:
            ext = HashExtractor()
            hashes = ext.hash_all(h_pw)
            algo_meta = {
                "md5":   ("MD5",    "32 chars", "❌ Broken — do not use for passwords"),
                "sha1":  ("SHA-1",  "40 chars", "❌ Deprecated — collision vulnerabilities"),
                "sha256":("SHA-256","64 chars", "⚠️ Acceptable but prefer bcrypt/Argon2"),
                "sha512":("SHA-512","128 chars","✅ Strong — use with unique salt per user"),
                "ntlm":  ("NTLM",   "32 chars", "❌ Windows legacy — no salt, easily cracked"),
            }
            for alg, hval in hashes.items():
                name, length, note = algo_meta.get(alg,(alg,"",""))
                st.markdown(f"""
<div class="abox" style="margin-bottom:8px">
  <div style="color:#00ff41;font-size:10px;letter-spacing:1px">{name} ({length})</div>
  <div style="color:#39d353;word-break:break-all;font-size:11px">{hval}</div>
  <div style="color:#4a8a4a;font-size:10px;margin-top:3px">{note}</div>
</div>""", unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("#### 🔍 Identify a Hash")
        id_h = st.text_input("Paste hash string", key="id_h")
        if id_h:
            identified = HashExtractor().identify_hash(id_h)
            st.markdown(f'<div class="abox info">Detected: <strong style="color:#00ff41">{identified}</strong></div>', unsafe_allow_html=True)

    with col_r:
        st.markdown("#### 🗂️ Simulated /etc/shadow Entries")
        shadow = report.get("hash_extraction", [])
        if shadow:
            df_sh = pd.DataFrame(shadow)
            show_cols = [c for c in ["username","algorithm","strength","hash","plaintext_demo"] if c in df_sh.columns]
            df_sh = df_sh[show_cols].copy()
            if "hash" in df_sh.columns:
                df_sh["hash"] = df_sh["hash"].str[:24] + "…"
            df_sh.columns = [c.replace("_"," ").title() for c in df_sh.columns]
            st.dataframe(df_sh, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.markdown("#### 📊 Algorithm Comparison")
        df_algo = pd.DataFrame([
            ("MD5",      "Very Weak",  "~10M/s",  "No",  "❌ Never"),
            ("SHA-1",    "Weak",       "~7M/s",   "No",  "❌ Never"),
            ("NTLM",     "Weak",       "~15M/s",  "No",  "❌ Never"),
            ("SHA-256",  "Moderate",   "~3M/s",   "No",  "⚠️  Legacy"),
            ("SHA-512",  "Strong",     "~1M/s",   "No",  "⚠️  Legacy"),
            ("bcrypt",   "Very Strong","~10/s",   "Yes", "✅ Recommended"),
            ("Argon2",   "Very Strong","~1/s",    "Yes", "✅ Recommended"),
        ], columns=["Algorithm","Strength","Crack Speed","Salted","Use"])
        st.dataframe(df_algo, use_container_width=True, hide_index=True)

# ══════════════════ TAB 3 — BRUTE FORCE ══════════════════════════════════════
with t3:
    st.markdown('<div class="sec-hdr">💥 Brute-Force Simulator</div>', unsafe_allow_html=True)
    sub1, sub2, sub3 = st.tabs(["Dictionary Attack Results","Time-to-Crack Estimator","Custom Attack"])

    with sub1:
        cd = report.get("brute_force_simulation",{})
        if cd:
            ca,cb,cc,cdd = st.columns(4)
            ca.metric("Words Tried",  f"{cd.get('attempts',0):,}")
            cb.metric("Cracked",      cd.get("cracked_count",0))
            cc.metric("Failed",       cd.get("failed_count",0))
            cdd.metric("Speed",       f"{cd.get('rate_per_sec',0):,}/s")

            cracked = cd.get("cracked",[])
            if cracked:
                st.markdown("##### 💥 Cracked Accounts")
                for c in cracked:
                    st.markdown(f'<div class="abox crit">🔓 <strong>{c["username"]}</strong> → plaintext: <code style="color:#ff3838">{c["plaintext"]}</code> | after {c["attempts"]:,} attempts | {c["algorithm"]}</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="abox good">✅ No hashes cracked — wordlist did not contain matching plaintexts for the target algorithm.</div>', unsafe_allow_html=True)

            failed = cd.get("failed_users",[])
            if failed:
                st.markdown(f"##### 🛡️ Resisted Attack: `{'`, `'.join(failed)}`")

    with sub2:
        estimates = report.get("brute_force_estimates",[])
        if estimates:
            df_est = pd.DataFrame([{
                "Password":  e["password"],
                "Length":    e["length"],
                "Algorithm": e["algorithm"],
                "Charset":   e["charset_size"],
                "Keyspace":  e["keyspace_display"],
                "Avg Crack Time": e["time_avg_display"],
                "Max Crack Time": e["time_max_display"],
            } for e in estimates])
            st.dataframe(df_est, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.markdown("##### 🧮 Custom Estimator")
        ep = st.text_input("Password to estimate", value="MyS3cur3P@ss!", key="ep")
        ea = st.selectbox("Algorithm", ["md5","sha1","sha256","sha512","ntlm","bcrypt"], key="ea")
        if ep:
            ext3 = HashExtractor(); sim4 = BruteForceSimulator(ext3)
            est_algo = "md5" if ea == "bcrypt" else ea
            est = sim4.brute_force_estimate(ep, est_algo)
            rates = {"md5":10_000_000,"sha1":7_000_000,"sha256":3_000_000,
                     "sha512":1_000_000,"ntlm":15_000_000,"bcrypt":10}
            rate = rates.get(ea, 1_000_000)
            ks   = est["keyspace"]
            secs = (ks/2)/rate
            disp = sim4._format_time(secs)
            e1,e2,e3,e4 = st.columns(4)
            e1.metric("Length",    ep.__len__())
            e2.metric("Charset",   est["charset_size"])
            e3.metric("Keyspace",  est["keyspace_display"])
            e4.metric("Avg Time",  disp)
            st.markdown(f'<div class="abox {"good" if secs > 86400 else "crit"}">💡 At {rate:,} hashes/sec ({ea.upper()}): average crack time = <strong style="color:#00ff41">{disp}</strong></div>', unsafe_allow_html=True)

    with sub3:
        st.markdown("##### 🧪 Custom Dictionary Attack")
        ca_hash = st.text_input("Target hash", key="ca_hash", placeholder="Paste MD5/SHA-1/SHA-256 hash here")
        ca_algo = st.selectbox("Algorithm", ["md5","sha1","sha256"], key="ca_algo")
        ca_wl   = st.text_area("Wordlist (one per line)", value="\n".join(COMMON_PASSWORDS[:20]), height=120, key="ca_wl")
        if st.button("💥 LAUNCH DICTIONARY ATTACK"):
            if ca_hash and ca_wl:
                words = [w.strip() for w in ca_wl.split("\n") if w.strip()]
                ext4  = HashExtractor(); sim5 = BruteForceSimulator(ext4)
                res   = sim5.dictionary_attack([{"username":"target","hash":ca_hash}], words, ca_algo)
                if res["cracked"]:
                    pw = res["cracked"][0]["plaintext"]
                    st.markdown(f'<div class="abox crit">💥 CRACKED: <code style="color:#ff3838;font-size:14px">{pw}</code> — found after {res["attempts"]:,} attempts in {res["elapsed_seconds"]}s</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="abox good">🛡️ Hash not found in {res["attempts"]:,} attempts ({res["elapsed_seconds"]}s elapsed)</div>', unsafe_allow_html=True)
            else:
                st.warning("Enter a target hash and wordlist.")

        st.markdown("---")
        st.markdown("##### 🔄 Incremental Brute-Force Demo")
        inc_target = st.text_input("Target plaintext (will hash internally for demo)", value="abc", key="inc_t")
        inc_chars  = st.selectbox("Charset", ["lower","digits","alnum"], key="inc_c")
        inc_len    = st.slider("Max length", 1, 5, 3, key="inc_l")
        inc_algo   = st.selectbox("Algorithm", ["md5","sha1","sha256"], key="inc_a")
        if st.button("🔄 RUN INCREMENTAL BRUTE-FORCE"):
            ext5 = HashExtractor(); sim6 = BruteForceSimulator(ext5)
            tgt_hash = ext5.hash_password(inc_target, inc_algo)
            st.markdown(f'<div class="abox info">Target hash ({inc_algo.upper()}): <code>{tgt_hash[:32]}…</code></div>', unsafe_allow_html=True)
            with st.spinner("Simulating…"):
                res2 = sim6.simulate_incremental(inc_chars, inc_len, tgt_hash, inc_algo)
            if res2["cracked"]:
                st.markdown(f'<div class="abox crit">💥 CRACKED: <code style="color:#ff3838">{res2["cracked"]}</code> after {res2["attempts"]:,} attempts in {res2["elapsed_sec"]}s</div>', unsafe_allow_html=True)
            else:
                cap_note = " (hit 500K attempt cap)" if res2["capped"] else ""
                st.markdown(f'<div class="abox good">🛡️ Not found after {res2["attempts"]:,} attempts{cap_note}</div>', unsafe_allow_html=True)

# ══════════════════ TAB 4 — STRENGTH ANALYZER ════════════════════════════════
with t4:
    st.markdown('<div class="sec-hdr">🛡️ Password Strength Analyzer</div>', unsafe_allow_html=True)
    col_l, col_r = st.columns([1,1])

    with col_l:
        st.markdown("#### 🔍 Live Password Analyzer")
        live_pw = st.text_input("Type a password", type="password", key="live_pw")
        if live_pw:
            ana    = PasswordStrengthAnalyzer()
            res    = ana.analyze(live_pw)
            grade  = res["grade"]
            score  = res["score"]
            colors = {"Very Weak":"#ff3838","Weak":"#ff7700","Moderate":"#ffaa00",
                      "Strong":"#39d353","Very Strong":"#00ff41"}
            bcol   = colors.get(grade,"#888")
            pct    = int((score/10)*100)

            st.markdown(f"""
<div class="tbox">
  <div class="tlabel">STRENGTH GRADE</div>
  <div class="tval" style="color:{bcol}">{grade}</div>
  <div class="sbar-wrap"><div class="sbar" style="width:{pct}%;background:{bcol}"></div></div>
  <div class="tsub">Score {score}/10  ·  Entropy {res['entropy_bits']} bits  ·  Length {res['length']}</div>
</div>""", unsafe_allow_html=True)

            checks = [
                ("Lowercase a-z", res["has_lower"]),
                ("Uppercase A-Z", res["has_upper"]),
                ("Digits 0-9",    res["has_digit"]),
                ("Symbols !@#",   res["has_symbol"]),
                ("Not a common password",   not res["is_common"]),
                ("No keyboard pattern",     not res["is_keyboard"]),
            ]
            for label, ok in checks:
                icon = "✅" if ok else "❌"
                col_c = "#39d353" if ok else "#ff3838"
                st.markdown(f'<div style="color:{col_c};font-size:12px;padding:2px 0">{icon} {label}</div>', unsafe_allow_html=True)

            if res["issues"]:
                st.markdown("**⚠️ Issues:**")
                for iss in res["issues"]:
                    st.markdown(f'<div class="abox warn">⚠️ {iss}</div>', unsafe_allow_html=True)
            if res["tips"]:
                st.markdown("**💡 Recommendations:**")
                for tip in res["tips"]:
                    st.markdown(f'<div class="abox info">💡 {tip}</div>', unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("#### 📋 Policy Checker")
        min_len   = st.slider("Minimum length", 6, 20, 12)
        req_upper = st.checkbox("Require uppercase",  True, key="p_up")
        req_digit = st.checkbox("Require digit",      True, key="p_dg")
        req_sym   = st.checkbox("Require symbol",     True, key="p_sy")
        blk_com   = st.checkbox("Block common passwords", True, key="p_cm")
        pol_pw    = st.text_input("Password to check against policy", key="pol_pw")
        if pol_pw:
            pol = {"min_length":min_len,"require_upper":req_upper,"require_digit":req_digit,
                   "require_symbol":req_sym,"block_common":blk_com}
            chk = PasswordStrengthAnalyzer().policy_check(pol_pw, pol)
            if chk["passed"]:
                st.markdown('<div class="abox good">✅ Password PASSES all policy requirements</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="abox crit">❌ Password FAILS policy:</div>', unsafe_allow_html=True)
                for v in chk["violations"]:
                    st.markdown(f'<div class="abox warn" style="margin-left:12px">• {v}</div>', unsafe_allow_html=True)

    with col_r:
        st.markdown("#### 📊 Batch Analysis Results")
        strength_data = report.get("strength_analysis",[])
        if strength_data:
            df_str = pd.DataFrame([{
                "Password (masked)": r["masked"],
                "Grade":  r["grade"],
                "Score":  f"{r['score']}/10",
                "Entropy":f"{r['entropy_bits']} bits",
                "Length": r["length"],
                "Issues": len(r["issues"]),
            } for r in strength_data])
            st.dataframe(df_str, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.markdown("#### 🔢 Entropy Reference Table")
        ent_df = pd.DataFrame([
            ("6 chars, lowercase only",    "28.2 bits",  "Very Weak",   "< 1 second (MD5)"),
            ("8 chars, lowercase only",    "37.6 bits",  "Weak",        "~2 seconds (MD5)"),
            ("8 chars, alnum",             "47.6 bits",  "Moderate",    "~28 minutes"),
            ("10 chars, full charset",     "65.6 bits",  "Strong",      "~12 years"),
            ("12 chars, full charset",     "78.7 bits",  "Very Strong", "~1.8M years"),
            ("16 chars, full charset",     "104.9 bits", "Very Strong", "Practically infinite"),
            ("Passphrase (4 words)",       "~51 bits",   "Strong",      "~centuries (dict)"),
        ], columns=["Password Type","Entropy","Grade","Approx Brute-Force Time (MD5)"])
        st.dataframe(ent_df, use_container_width=True, hide_index=True)

# ══════════════════ TAB 5 — ANALYTICS ════════════════════════════════════════
with t5:
    st.markdown('<div class="sec-hdr">📊 Analytics Dashboard</div>', unsafe_allow_html=True)

    strength_data = report.get("strength_analysis",[])
    grades = Counter(r["grade"] for r in strength_data)

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("##### Grade Distribution")
        if grades:
            df_g = pd.DataFrame(list(grades.items()), columns=["Grade","Count"])
            df_g = df_g.sort_values("Count", ascending=False)
            st.bar_chart(df_g.set_index("Grade"), color="#00ff41", height=240)

    with col_b:
        st.markdown("##### Entropy Distribution")
        if strength_data:
            entropies = [r["entropy_bits"] for r in strength_data]
            df_ent = pd.DataFrame({"Entropy (bits)": entropies,
                                   "Password": [r["masked"] for r in strength_data]})
            st.bar_chart(df_ent.set_index("Password"), color="#39d353", height=240)

    st.markdown("---")
    col_c, col_d = st.columns(2)
    with col_c:
        st.markdown("##### Issue Frequency")
        all_issues = []
        for r in strength_data:
            all_issues.extend(r.get("issues",[]))
        if all_issues:
            iss_counts = Counter(all_issues)
            df_iss = pd.DataFrame(list(iss_counts.items()), columns=["Issue","Count"]).sort_values("Count",ascending=False)
            st.dataframe(df_iss, use_container_width=True, hide_index=True)

    with col_d:
        st.markdown("##### Score vs Length Scatter")
        if strength_data:
            df_sc = pd.DataFrame([{"Length":r["length"],"Score":r["score"],"Grade":r["grade"]}
                                   for r in strength_data])
            st.dataframe(df_sc.sort_values("Score", ascending=False), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("##### Hash Algorithm Vulnerability Summary")
    vuln_df = pd.DataFrame([
        ("MD5",    "1996",  "Collision attacks, rainbow tables",   "CRITICAL", "Replace immediately"),
        ("SHA-1",  "2005",  "SHAttered collision attack (2017)",   "HIGH",     "Phase out immediately"),
        ("NTLM",   "1993",  "No salt, pass-the-hash attacks",      "HIGH",     "Replace with Kerberos/MFA"),
        ("SHA-256","2001",  "No salt — vulnerable to precomputed", "MEDIUM",   "Add unique salt per user"),
        ("SHA-512","2001",  "No salt — same as SHA-256 concern",   "MEDIUM",   "Add unique salt per user"),
        ("bcrypt", "1999",  "None significant — slow by design",   "LOW",      "✅ Recommended"),
        ("Argon2", "2015",  "None — memory-hard design",           "LOWEST",   "✅ Best practice 2025"),
    ], columns=["Algorithm","Year","Vulnerability","Risk","Action"])
    st.dataframe(vuln_df, use_container_width=True, hide_index=True)

# ══════════════════ TAB 6 — AUDIT REPORT ═════════════════════════════════════
with t6:
    st.markdown('<div class="sec-hdr">📄 Security Audit Report</div>', unsafe_allow_html=True)

    col_dl, col_ts = st.columns([1,3])
    with col_dl:
        json_str = json.dumps(report, indent=2, default=str)
        st.download_button(
            label="⬇️  DOWNLOAD REPORT",
            data=json_str,
            file_name=f"passwd_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )
    with col_ts:
        meta = report.get("report_metadata",{})
        st.markdown(f'<div style="color:#4a8a4a;font-size:11px">Generated: {meta.get("generated_at","")}  |  Tool: {meta.get("tool","")}  |  Mode: {meta.get("mode","")}</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 🛡️ Security Recommendations")
    recs = report.get("recommendations",[])
    for i, rec in enumerate(recs, 1):
        st.markdown(f'<div class="abox good">{"0"+str(i) if i<10 else str(i)}. {rec}</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 📋 Policy Violations Detected")
    violations = report.get("policy_violations",[])
    if violations:
        for v in violations:
            pw = v.get("password","")
            viols = v.get("violations",[])
            st.markdown(f'<div class="abox warn"><strong style="color:#ffaa00">{pw[:3]}{"*"*(len(pw)-3)}</strong> — {len(viols)} violation(s): {", ".join(viols)}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="abox good">✅ No policy violations detected in test set</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 🗂️ Full JSON Report")
    st.code(json_str[:5000] + ("\n\n... (truncated — download for full report)" if len(json_str)>5000 else ""),
            language="json")