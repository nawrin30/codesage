import ast, json, shutil, subprocess, sys, tempfile
from pathlib import Path

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

def finding(rule, severity, line, title, explanation, fix, snippet="", source="Static analysis", category="Quality"):
    return {"id": rule + "-" + str(line or 0) + "-" + title[:12].replace(" ", ""),
            "rule_id": rule, "severity": severity, "line": line or 1, "title": title,
            "explanation": explanation, "suggested_fix": fix, "snippet": snippet,
            "source": source, "category": category}

def analyze_python(code: str) -> list[dict]:
    findings = []
    lines = code.splitlines()
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        line = exc.lineno or 1
        findings.append(finding("PY-SYNTAX", "Critical", line, "Python syntax error",
            f"{exc.msg}. Python cannot parse this source until the syntax is corrected.",
            "Correct the syntax near this line and run the review again.",
            lines[line-1].strip() if 0 < line <= len(lines) else "", category="Correctness"))
        return findings

    for node in ast.walk(tree):
        line = getattr(node, "lineno", 1)
        snippet = lines[line-1].strip() if 0 < line <= len(lines) else ""
        if isinstance(node, (ast.Call,)) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            findings.append(finding("PY-DYNAMIC-EXEC", "High", line, f"Use of {node.func.id}()",
                "Dynamic execution can turn untrusted text into executable code and make behavior difficult to audit.",
                "Avoid dynamic execution. Parse data with json or use an explicit, validated dispatch table where possible.",
                snippet, category="Security"))
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            findings.append(finding("PY-BARE-EXCEPT", "Medium", line, "Bare except clause",
                "A bare except catches nearly every exception, including interruption signals, and can hide defects.",
                "Catch the specific exception types the code expects and handle them deliberately.", snippet))
        if isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name) and node.type.id == "Exception":
            findings.append(finding("PY-BROAD-EXCEPT", "Low", line, "Broad exception handling",
                "Catching Exception may conceal unrelated failures if the handler does not re-raise or report them.",
                "Catch narrower exception types and log or surface unexpected errors.", snippet))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"system", "popen"}:
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                findings.append(finding("PY-OS-COMMAND", "High", line, "Shell command invocation",
                    "Shell command strings can be risky when they include untrusted input.",
                    "Prefer subprocess.run with a list of arguments and shell=False; validate external input.", snippet, category="Security"))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                findings.append(finding("PY-SHELL-TRUE", "High", line, "subprocess shell=True",
                    "shell=True can allow command injection if any part of the command is influenced by untrusted input.",
                    "Use an argument list and remove shell=True unless a shell is genuinely required.", snippet, category="Security"))
        if isinstance(node, ast.FunctionDef) and len(node.body) > 35:
            findings.append(finding("PY-LONG-FUNCTION", "Low", line, "Long function",
                f"This function contains {len(node.body)} top-level statements, which can make it harder to test and maintain.",
                "Consider extracting cohesive steps into smaller functions with clear names.", snippet))
        if isinstance(node, ast.Compare) and any(isinstance(op, ast.Eq) for op in node.ops):
            if any(isinstance(v, ast.Constant) and v.value is None for v in node.comparators):
                findings.append(finding("PY-NONE-EQ", "Low", line, "Compare with None using ==",
                    "PEP 8 recommends identity checks for None.",
                    "Use `is None` or `is not None`.", snippet))
    if shutil.which("ruff"):
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "submitted.py"
                path.write_text(code, encoding="utf-8")
                proc = subprocess.run(["ruff", "check", "--output-format", "json", str(path)],
                    capture_output=True, text=True, timeout=8, check=False)
                for item in json.loads(proc.stdout or "[]"):
                    loc = item.get("location", {})
                    findings.append(finding(item.get("code") or "RUFF", "Low", loc.get("row", 1),
                        item.get("message", "Ruff finding"), "Reported by Ruff static linting.",
                        item.get("fix", {}).get("message") or "Review the lint message and update the code.",
                        lines[(loc.get("row", 1)-1)] if 0 < loc.get("row", 1) <= len(lines) else ""))
        except Exception:
            pass
    if shutil.which("bandit"):
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "submitted.py"
                path.write_text(code, encoding="utf-8")
                proc = subprocess.run(["bandit", "-f", "json", "-q", str(path)],
                    capture_output=True, text=True, timeout=8, check=False)
                payload = json.loads(proc.stdout or "{}")
                for item in payload.get("results", []):
                    sev = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}.get(item.get("issue_severity"), "Low")
                    ln = item.get("line_number", 1)
                    findings.append(finding(item.get("test_id", "BANDIT"), sev, ln,
                        item.get("issue_text", "Bandit finding"), "Reported by Bandit security analysis.",
                        item.get("more_info") or "Review the security finding and validate the fix.",
                        lines[ln-1] if 0 < ln <= len(lines) else "", category="Security"))
        except Exception:
            pass
    findings.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9), x["line"]))
    return findings
