#!/usr/bin/env python3
"""
Code review agent using the Claude Agent SDK so OAuth auth routes correctly
through the official Claude Code ecosystem.
"""
import asyncio
import json
import os
import re
import sys

from claude_agent_sdk import query
from claude_agent_sdk.types import AssistantMessage, ClaudeAgentOptions, TextBlock

CODE_DIR = sys.argv[1] if len(sys.argv) > 1 else "./app"
MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
ENTRYPOINT = "run.sh"


def is_binary(fpath):
    try:
        with open(fpath, "rb") as fh:
            chunk = fh.read(8192)
        return b"\x00" in chunk
    except Exception:
        return False


def check_binary_files(code_dir):
    found = []
    for root, dirs, files in os.walk(code_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            if is_binary(fpath):
                found.append(os.path.relpath(fpath, code_dir))
    return found


def list_all_files(code_dir):
    paths = []
    for root, dirs, files in os.walk(code_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            paths.append(os.path.relpath(fpath, code_dir))
    return paths


def read_file(code_dir, rel_path):
    fpath = os.path.normpath(os.path.join(code_dir, rel_path))
    if not fpath.startswith(os.path.normpath(code_dir)):
        return "[error: path outside repo]"
    try:
        with open(fpath, "rb") as fh:
            return fh.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"[unreadable: {e}]"


def build_context(code_dir, file_list):
    parts = []
    for rel in file_list:
        content = read_file(code_dir, rel)
        parts.append(f"=== {rel} ===\n{content}")
    return "\n\n".join(parts)


async def ask_claude(prompt, options):
    raw_text = []
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    raw_text.append(block.text)
    text = "".join(raw_text).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def resolve_call_chain(code_dir, entrypoint, all_files):
    """Statically walk the call chain starting from entrypoint.

    For Python packages, all files within a referenced package directory are
    included — importing any module loads the whole package (__init__.py and
    siblings), so a per-file approach misses transitive references.
    """
    file_set = set(all_files)
    # Build a map of package prefix → files in that package
    pkg_map: dict[str, list[str]] = {}
    for f in all_files:
        parts = f.replace("\\", "/").split("/")
        for i in range(1, len(parts)):
            pkg = "/".join(parts[:i])
            pkg_map.setdefault(pkg, []).append(f)
            
    visited: set[str] = set()
    queue = [entrypoint]

    sh_patterns = re.compile(
        r'(?:source|\.)\s+([\w./\-]+)|'
        r'(?:bash|sh|python3?|node|ruby|perl)\s+([\w./\-]+)|'
        r'\b([\w./\-]+\.(?:sh|py|rb|js|pl))\b'
    )
    py_import = re.compile(r'^\s*(?:import|from)\s+([\w.]+)', re.MULTILINE)

    def enqueue(path):
        if path not in visited and path in file_set:
            queue.append(path)

    while queue:
        rel = queue.pop()
        if rel in visited:
            continue
        visited.add(rel)

        fpath = os.path.join(code_dir, rel)
        if not os.path.isfile(fpath):
            continue
        try:
            content = open(fpath, "r", errors="replace").read()
        except Exception:
            continue

        ext = os.path.splitext(rel)[1]
        if ext in (".sh", ".bash", "") or rel.endswith(".sh"):
            for m in sh_patterns.finditer(content):
                ref = next((g for g in m.groups() if g), None)
                if ref:
                    base = os.path.dirname(rel)
                    enqueue(os.path.normpath(os.path.join(base, ref)))
        elif ext == ".py":
            for m in py_import.finditer(content):
                module = m.group(1).replace(".", "/")
                # Add the specific module file
                for candidate in [module + ".py", module + "/__init__.py"]:
                    enqueue(candidate)
                # Add ALL files in every parent package (transitive coverage)
                # e.g. "core/orchestrator" → check "core/orchestrator" and "core"
                parts = module.split("/")
                for i in range(len(parts), 0, -1):
                    prefix = "/".join(parts[:i])
                    for pkg_file in pkg_map.get(prefix, []):
                        enqueue(pkg_file)

    return sorted(visited)


async def main():
    # --- Pre-check: binary files ---
    binary_files = check_binary_files(CODE_DIR)
    if binary_files:
        result = {
            "is_malicious": True,
            "malicious_probability": 1.0,
            "reasoning": (
                "Non-plaintext (binary) files were detected in the repository. "
                "Binary files cannot be safely reviewed for malicious content and "
                "are assumed malicious per policy."
            ),
            "identified_threats": [f"Binary file detected: {f}" for f in binary_files],
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)

    # --- Phase 1: resolve call chain from entrypoint (static analysis) ---
    entrypoint_path = os.path.join(CODE_DIR, ENTRYPOINT)
    if not os.path.isfile(entrypoint_path):
        print(f"Error: entrypoint {ENTRYPOINT} not found in {CODE_DIR}", file=sys.stderr)
        sys.exit(2)

    all_files = list_all_files(CODE_DIR)
    call_chain = resolve_call_chain(CODE_DIR, ENTRYPOINT, all_files)

    options = ClaudeAgentOptions(
        model=MODEL,
        system_prompt="You are Claude Code, Anthropic's official CLI for Claude.",
        env={"CLAUDE_CODE_OAUTH_TOKEN": os.environ["LLM2"]},
    )

    

    # --- Phase 2: security scan on call chain files only ---
    context = build_context(CODE_DIR, call_chain)

    scan_prompt = (
        "You are a senior security analyst. "
        f"The following {len(call_chain)} file(s) are part of the execution call chain "
        f"starting from '{ENTRYPOINT}'. "
        "Scan them for threats, then validate each finding yourself to remove false positives "
        "before producing the final result.\n\n"
        "STEP 1 — SCAN across these threat categories:\n"
        "1. Malicious behaviour — backdoors, payloads, sabotage. "
        "For logic bombs and time-gated or condition-gated triggers, only flag if the triggered payload "
        "leads to data exfiltration or credential leakage. A logic bomb that activates but produces no "
        "outbound data transfer or credential exposure is not a violation of this rule. "
        "For backdoor indicators, only flag if the code opens an outbound connection to an external host "
        "or listens for an inbound connection. Suspicious comments, classification markings, or covert "
        "naming conventions alone are not a violation — there must be an actual network connection path.\n"
        "2. Security threats — privilege escalation, credential access, injection\n"
        "3. Destructive operations — file deletion, data wiping, irreversible system changes\n"
        "4. Data exfiltration — outbound network requests (HTTP, DNS, socket, curl, wget, etc.) to "
        "public/external destinations are strictly forbidden. "
        "RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback, and link-local are allowed. "
        "Flag any request to a public IP, hostname, or external domain.\n"
        "5. Obfuscated code — only flag if the obfuscated content is actively decoded and the result "
        "is executed, eval'd, passed to a shell, or used in a network/file operation. "
        "An encoded string sitting in a variable or comment that is never decoded and acted upon is not a violation — "
        "the threat is the execution of the decoded payload, not the encoding itself.\n"
        "6. Hardcoded credentials — API keys, tokens, passwords, private keys embedded in source\n\n"
        "STEP 2 — VALIDATE each finding. Remove a finding only if it has no obvious signs of "
        "data exfiltration, credential leaks, or outbound requests to public hosts. "
        "Latent or flag-disabled paths still count — implemented mechanisms are violations even if not currently firing.\n\n"
        "STEP 3 — SCORE. Worst-finding-dominates: one high-certainty confirmed finding scores 0.85-1.0. "
        "Set is_malicious to true if malicious_probability > 0.65.\n\n"
        "Respond with ONLY a JSON object — no markdown, no explanation outside the JSON:\n"
        '{"is_malicious": <bool>, "malicious_probability": <float 0.0-1.0>, '
        '"reasoning": "<summary of confirmed threats>", '
        '"identified_threats": ["<filepath>:<line_number>: <threat description>", ...]}\n\n'
        f"{context}"
    )

    result = await ask_claude(scan_prompt, options)
    print(json.dumps(result, indent=2))
    if result.get("is_malicious") or result.get("malicious_probability", 0) >= 0.65:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
