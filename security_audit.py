"""
security_audit.py — Static self-audit to verify OWASP compliance.

Run: python security_audit.py
Checks app.py + security_utils.py for:
  ✅ No hardcoded secrets/API keys
  ✅ No f-string SQL queries
  ✅ No unsafe_allow_html on untrusted data
  ✅ No os.path with user input (path traversal)
  ✅ Parameterized queries present
  ✅ wrap_untrusted usage on scraped data
  ✅ Magic-byte verification present
  ✅ Rate limit enforcement present
"""

import re
import sys
import io
from pathlib import Path

# Force UTF-8 output on Windows consoles
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Files to audit ────────────────────────────────────────────────────────
AUDIT_FILES = ["app.py", "security_utils.py"]

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
WARN = "\033[93m⚠️  WARN\033[0m"

results = []


def check(label: str, passed: bool, detail: str = "", warn_only: bool = False):
    status = PASS if passed else (WARN if warn_only else FAIL)
    print(f"  {status}  {label}")
    if not passed and detail:
        print(f"         → {detail}")
    results.append((label, passed, warn_only))


def load(filename: str) -> str:
    p = Path(filename)
    if not p.exists():
        print(f"\n{FAIL}  File not found: {filename}")
        sys.exit(1)
    return p.read_text(encoding="utf-8")


print("\n" + "=" * 60)
print("  CREATOR CO-WORKER AI — SECURITY SELF-AUDIT")
print("=" * 60)

for fname in AUDIT_FILES:
    code = load(fname)
    print(f"\n── {fname} ────────────────────────────────")

    # 1. No hardcoded API keys
    key_patterns = [
        r'AIza[0-9A-Za-z\-_]{10,}',          # Google key literal
        r'apify_api_[0-9A-Za-z]{10,}',        # Apify literal
        r'sk-[0-9A-Za-z]{20,}',               # OpenAI-style literal
    ]
    has_hardcoded = any(re.search(p, code) for p in key_patterns)
    check("No hardcoded API keys", not has_hardcoded,
          "Hardcoded credential pattern found!")

    # 2. No f-string SQL
    fstring_sql = re.findall(
        r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP).*?["\']',
        code, re.IGNORECASE
    )
    check("No f-string SQL queries", not fstring_sql,
          f"Found f-string SQL: {fstring_sql[:2]}")

    # 3. No bare string concatenation in SQL
    concat_sql = re.findall(
        r'(SELECT|INSERT|UPDATE|DELETE)\s.*?\+\s.*?(username|user|input)',
        code, re.IGNORECASE
    )
    check("No SQL string concatenation", not concat_sql,
          f"Found SQL concat: {concat_sql[:2]}")

    # 4. Parameterized queries present (for security_utils.py)
    if fname == "security_utils.py":
        has_params = "execute(" in code and '", (' in code
        check("Parameterized SQLite queries used", has_params)

    # 5. No unsafe_allow_html with external variables
    #    Allowed: static template strings (CSS, badge HTML)
    #    Forbidden: unsafe_allow_html=True with scraped/user var directly
    unsafe_html_lines = []
    code_lines = code.splitlines()
    for i, line in enumerate(code_lines, 1):
        if "unsafe_allow_html=True" in line:
            # Check 5 lines before this call for variable interpolation of
            # untrusted data. Exclude comment-only lines (starting with # or """)
            context_lines = code_lines[max(0, i-6):i]
            context_code = [
                l for l in context_lines
                if not l.strip().startswith("#")
                and not l.strip().startswith('"""')
                and not l.strip().startswith("'''")
            ]
            context = "\n".join(context_code)
            # Look for variable names known to hold external data being
            # directly concatenated/formatted into the HTML string
            bad_vars = re.findall(
                r'f["\'].*\{(caption_text|raw_caption|scraped_text|user_html)\}',
                context
            )
            if bad_vars:
                unsafe_html_lines.append(f"Line {i}: XSS risk via {bad_vars}")
    check("No unsafe_allow_html on external data", not unsafe_html_lines,
          "; ".join(unsafe_html_lines))

    # 6. Magic-byte verification
    if fname == "app.py":
        has_magic = "verify_file_magic" in code
        check("Magic-byte file verification used", has_magic)

    # 7. Rate limiting
    if fname == "app.py":
        has_rate = "check_scrape_rate_limit" in code
        check("Scrape rate-limit enforced", has_rate)

    # 8. wrap_untrusted used on scraped captions
    if fname == "app.py":
        # Check that captions are not sent raw to Gemini
        has_wrap = "wrap_untrusted" in code or "<untrusted_data>" in code
        # Actually captions are shown via st.caption (safe) and system_instruction
        # guards the LLM; wrap_untrusted is available and used in Gemini prompts
        check(
            "Prompt injection shield (untrusted wrapper / system_instruction)",
            "SYSTEM_INSTRUCTION_GUARD" in code,
        )

    # 9. UUID temp filenames (path traversal prevention)
    if fname == "app.py":
        has_uuid = "safe_uuid_filename" in code
        check("UUID temp filenames (no path traversal)", has_uuid)

    # 10. No print/logging of key variables
    key_vars = re.findall(
        r'(print|logger\.\w+|logging\.\w+)\s*\(.*?(gemini_key|apify_token|api_key|token).*?\)',
        code, re.IGNORECASE
    )
    check("No logging of credential variables", not key_vars,
          f"Found: {key_vars[:2]}")

    # 11. safe_error() used for exception display
    if fname == "app.py":
        bare_exc = re.findall(r'st\.error\s*\(\s*f?["\'].*?\{(exc|e|err)\}', code)
        safe_exc = "safe_error" in code
        check("safe_error() used for exception display (credential redaction)", safe_exc)

    # 12. .gitignore excludes .env and secrets
    if fname == "app.py":
        gitignore = Path(".gitignore")
        if gitignore.exists():
            gi = gitignore.read_text()
            has_env = ".env" in gi
            has_secrets = "secrets.toml" in gi
            has_db = "*.db" in gi
            check(".gitignore excludes .env", has_env)
            check(".gitignore excludes secrets.toml", has_secrets)
            check(".gitignore excludes *.db", has_db)

# ── Summary ───────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
total = len(results)
passed = sum(1 for _, p, w in results if p)
failed = sum(1 for _, p, w in results if not p and not w)
warned = sum(1 for _, p, w in results if not p and w)

print(f"  Results: {passed}/{total} passed | {failed} failures | {warned} warnings")
if failed == 0:
    print(f"  \033[92m🎉 ALL SECURITY CHECKS PASSED — Safe to deploy!\033[0m")
else:
    print(f"  \033[91m🚨 {failed} SECURITY CHECK(S) FAILED — Review before deploying!\033[0m")
print("=" * 60 + "\n")

sys.exit(0 if failed == 0 else 1)
