#!/usr/bin/env python3
"""
build_field_guide - render the framework and every playbook into a printable "SOC IR Field Guide".

Usage:
    python tools/build_field_guide.py --out field-guide/index.html
    python tools/build_field_guide.py --out field-guide/index.html --pdf field-guide/SOC-IR-Field-Guide.pdf

The PDF step uses headless Chrome / Chromium (found automatically, or pass --chrome). Mermaid decision
trees are rendered in the browser, and the build fails if any diagram does not render.
Standard library only (Python 3.10+).
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"
AREAS = [
    ("identity", "Identity", "🔑"), ("email", "Email", "📧"), ("saas", "SaaS & Microsoft 365 data", "🗂️"),
    ("endpoint", "Endpoint", "💻"), ("cloud", "Cloud", "☁️"), ("network", "Network & edge", "🌐"),
    ("data", "Data security", "🗄️"),
]
FRAMEWORK = ["triage-method.md", "severity-matrix.md", "escalation-and-handover.md", "incident-response-lifecycle.md"]
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ---------------------------------------------------------------- markdown (the subset the repo uses)
def front_matter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---", 4)
    meta = {}
    for line in text[4:end].splitlines():
        k, sep, v = line.partition(":")
        if sep:
            meta[k.strip()] = v.strip()
    return meta, text[end + 4:].lstrip("\n")


class Linker:
    """Maps relative .md links to in-document anchors."""

    def __init__(self, anchors: dict[Path, str]):
        self.anchors = anchors

    def inline(self, s: str, base: Path) -> str:
        parts = re.split(r"(`[^`]+`)", s)
        out = []
        for p in parts:
            if p.startswith("`") and p.endswith("`") and len(p) > 1:
                out.append(f"<code>{html.escape(p[1:-1])}</code>")
                continue
            p = html.escape(p, quote=False)
            p = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", p)
            p = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", p)
            p = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", lambda m: self.link(m.group(1), m.group(2), base), p)
            out.append(p)
        return "".join(out)

    def link(self, text: str, target: str, base: Path) -> str:
        if target.startswith("http"):
            return f'<a href="{target}">{text}</a>'
        path = (base.parent / target.split("#")[0]).resolve()
        if path in self.anchors:
            return f'<a href="#{self.anchors[path]}">{text}</a>'
        return text


def md_to_html(md: str, base: Path, linker: Linker, shift: int = 0) -> str:
    lines = md.split("\n")
    out: list[str] = []
    i = 0
    list_stack: list[str] = []
    para: list[str] = []

    def flush_para():
        if para:
            out.append("<p>" + linker.inline(" ".join(para), base) + "</p>")
            para.clear()

    def close_lists(to: int = 0):
        while len(list_stack) > to:
            out.append(f"</li></{list_stack.pop()}>")

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        fence = re.match(r"^(\s*)```(\w*)\s*$", line)
        if fence:
            flush_para()
            lang = fence.group(2)
            body = []
            i += 1
            while i < len(lines) and not re.match(r"^\s*```\s*$", lines[i]):
                body.append(lines[i])
                i += 1
            indent = min((len(b) - len(b.lstrip()) for b in body if b.strip()), default=0)
            code = "\n".join(b[indent:] for b in body)
            if lang == "mermaid":
                if not list_stack:
                    close_lists()
                out.append(f'<div class="tree"><pre class="mermaid">{html.escape(code)}</pre></div>')
            else:
                label = {"kql": "Microsoft Sentinel · KQL", "": "Google SecOps · UDM search"}.get(lang, lang.upper())
                if lang == "" and not re.search(r"\b(metadata|principal|target|network|security_result|extensions)\.", code):
                    label = "Template"
                out.append(f'<div class="code"><span class="lang">{label}</span><pre>{html.escape(code)}</pre></div>')
            i += 1
            continue
        h = re.match(r"^(#{1,4})\s+(.*)$", line)
        if h:
            flush_para(); close_lists()
            level = min(6, len(h.group(1)) + shift)
            out.append(f"<h{level}>{linker.inline(h.group(2), base)}</h{level}>")
            i += 1
            continue
        if stripped.startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            flush_para(); close_lists()
            head = [c.strip() for c in stripped.strip("|").split("|")]
            rows = []
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            t = ["<table><thead><tr>" + "".join(f"<th>{linker.inline(c, base)}</th>" for c in head) + "</tr></thead><tbody>"]
            for r in rows:
                t.append("<tr>" + "".join(f"<td>{linker.inline(c, base)}</td>" for c in r) + "</tr>")
            out.append("".join(t) + "</tbody></table>")
            continue
        if stripped.startswith(">"):
            flush_para(); close_lists()
            quote = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip()[1:].strip())
                i += 1
            out.append('<blockquote>' + linker.inline(" ".join(quote), base) + "</blockquote>")
            continue
        li = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if li:
            flush_para()
            kind = "ol" if li.group(2)[0].isdigit() else "ul"
            depth = len(li.group(1)) // 2 + 1
            if len(list_stack) < depth:
                attr = f' start="{li.group(2)[:-1]}"' if kind == "ol" else ""
                out.append(f"<{kind}{attr}><li>")
                list_stack.append(kind)
            else:
                close_lists(depth)
                if list_stack and list_stack[-1] != kind:
                    close_lists(depth - 1)
                    out.append(f"<{kind}><li>")
                    list_stack.append(kind)
                else:
                    out.append("</li><li>")
            out.append(linker.inline(li.group(3), base))
            i += 1
            continue
        if not stripped:
            flush_para()
            # a blank line ends a list unless the next line continues it (indented content or another item)
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if list_stack and not (nxt.startswith(" ") or re.match(r"^\s*([-*]|\d+\.)\s", nxt)):
                close_lists()
            i += 1
            continue
        if stripped == "---":
            flush_para(); close_lists()
            i += 1
            continue
        if list_stack and line.startswith(" "):
            out.append(" " + linker.inline(stripped, base))
        else:
            para.append(stripped)
        i += 1
    flush_para(); close_lists()
    return "\n".join(out)


# ---------------------------------------------------------------- document
def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def build(version: str) -> str:
    playbooks = []
    for p in sorted((ROOT / "playbooks").rglob("*.md")):
        if p.name == "INDEX.md":
            continue
        meta, body = front_matter(p.read_text(encoding="utf-8"))
        playbooks.append((p.resolve(), meta, body, p.parent.name))
    anchors = {p: slug(m["id"]) for p, m, _, _ in playbooks}
    fw = [(ROOT / "framework" / f).resolve() for f in FRAMEWORK]
    for f in fw:
        anchors[f] = "fw-" + slug(f.stem)
    linker = Linker(anchors)

    by_area = defaultdict(list)
    for item in playbooks:
        by_area[item[3]].append(item)
    for a in by_area:
        by_area[a].sort(key=lambda x: x[1]["id"])
    techniques = defaultdict(list)
    for p, m, _, _ in playbooks:
        for t in [t.strip() for t in m.get("mitre", "").split(",") if t.strip().startswith("T")]:
            techniques[t].append(m)
    n_y = len({r.strip() for _, m, _, _ in playbooks for r in m.get("related_rules", "").split(",") if r.strip()})
    n_k = len({r.strip() for _, m, _, _ in playbooks for r in m.get("related_kql", "").split(",") if r.strip()})

    parts = []
    # cover
    parts.append(f"""
<section class="cover">
  <div class="kicker">Security Operations · Incident Response</div>
  <h1>SOC IR<br>Field Guide</h1>
  <p class="sub">{len(playbooks)} decision-tree playbooks for the alerts SOC teams see every day, from first triage to containment.</p>
  <div class="stats">
    <div><b>{len(playbooks)}</b><span>playbooks</span></div>
    <div><b>{len(techniques)}</b><span>ATT&amp;CK techniques</span></div>
    <div><b>{n_y}</b><span>Google SecOps rules linked</span></div>
    <div><b>{n_k}</b><span>Sentinel rules linked</span></div>
  </div>
  <div class="author"><b>Rizwan Ahmed</b><br>Security Engineer · SIEM / SOAR, DAM, HSM<br>
  <span>github.com/rizwancyberlock-svg/soc-triage-playbooks · Version {version} · MIT licensed</span></div>
</section>""")
    # how to use
    parts.append("""
<section class="page">
  <h2 id="how-to-use">How to use this guide</h2>
  <p>Every playbook answers one alert family with the same structure, so an analyst can work an unfamiliar alert in minutes:</p>
  <table><thead><tr><th>Section</th><th>What it gives you</th></tr></thead><tbody>
  <tr><td><strong>When this fires</strong></td><td>The detections that lead here, in Google SecOps (YARA-L) and Microsoft Sentinel (KQL)</td></tr>
  <tr><td><strong>Triage decision tree</strong></td><td>The questions that matter, in order, ending in a verdict and an action</td></tr>
  <tr><td><strong>Investigation steps</strong></td><td>Copy-paste queries: Sentinel KQL (each one compiled against the real Sentinel schemas) and SecOps UDM searches</td></tr>
  <tr><td><strong>True vs false positive</strong></td><td>The indicators that separate an attack from normal business</td></tr>
  <tr><td><strong>Containment &amp; response</strong></td><td>What to do now, and what to harden afterwards</td></tr>
  <tr><td><strong>Escalation criteria / Evidence</strong></td><td>When to call IR, and what to preserve for them</td></tr>
  </tbody></table>
  <p>Start with the <a href="#fw-triage-method">universal triage method</a> and the <a href="#fw-severity-matrix">severity matrix</a>. They apply to every alert. Placeholders such as <code>&lt;USER_UPN&gt;</code> must be replaced before running a query. Thresholds and table availability depend on your licences and connectors.</p>
  <p class="note">Queries and decisions are starting points written for typical enterprise environments. Validate them against your own data, policies and legal requirements before relying on them.</p>
</section>""")
    # contents
    toc = ['<section class="page toc"><h2 id="contents">Contents</h2><h3>Part 1 · Framework</h3><ol class="toc-list">']
    for f in fw:
        title = re.search(r"^#\s+(.*)$", f.read_text(encoding="utf-8"), re.M).group(1)
        toc.append(f'<li><a href="#{anchors[f]}">{html.escape(title)}</a></li>')
    toc.append("</ol><h3>Part 2 · Playbooks</h3>")
    for key, name, icon in AREAS:
        if key not in by_area:
            continue
        toc.append(f'<div class="toc-area"><h4>{icon} <a href="#area-{key}">{name}</a></h4><ul class="toc-list">')
        for p, m, _, _ in by_area[key]:
            toc.append(f'<li><a href="#{anchors[p]}"><span class="pid">{m["id"]}</span> {html.escape(m["title"])}</a> <span class="sev {m["severity"].lower()}">{m["severity"]}</span></li>')
        toc.append("</ul></div>")
    toc.append('<h3>Appendix</h3><ol class="toc-list"><li><a href="#attack-index">ATT&amp;CK technique index</a></li></ol></section>')
    parts.append("".join(toc))
    # framework
    parts.append('<section class="divider"><div class="kicker">Part 1</div><h1>Framework</h1><p>The method that applies to every alert.</p></section>')
    for f in fw:
        body = md_to_html(f.read_text(encoding="utf-8"), f, linker, shift=1)
        body = body.replace("<h2>", f'<h2 id="{anchors[f]}">', 1)
        parts.append(f'<section class="page fw">{body}</section>')
    # playbooks
    parts.append('<section class="divider"><div class="kicker">Part 2</div><h1>Playbooks</h1>'
                 f'<p>{len(playbooks)} alert families across identity, email, SaaS, endpoint, cloud, network and data security.</p></section>')
    for key, name, icon in AREAS:
        if key not in by_area:
            continue
        first = True
        for p, m, body, _ in by_area[key]:
            content = md_to_html(body, p, linker, shift=1)
            content = re.sub(r"^<h2>.*?</h2>", "", content, count=1)
            area_anchor = f' id="area-{key}"' if first else ""
            first = False
            tags = "".join(f'<span class="tech">{html.escape(t.strip())}</span>' for t in m.get("mitre", "").split(","))
            parts.append(f"""
<section class="page playbook"{area_anchor}>
  <div class="pb-head" id="{anchors[p]}">
    <div class="pb-area">{icon} {name} · <span class="pid">{m['id']}</span></div>
    <h2>{html.escape(m['title'])}</h2>
    <div class="pb-meta"><span class="sev {m['severity'].lower()}">{m['severity']}</span>{tags}</div>
  </div>
  {content}
  <div class="back"><a href="#contents">▲ Contents</a></div>
</section>""")
    # attack index
    rows = []
    for t in sorted(techniques, key=lambda x: [int(n) if n.isdigit() else n for n in re.split(r"[T.]", x) if n]):
        links = ", ".join(f'<a href="#{slug(m["id"])}">{m["id"]}</a>' for m in sorted(techniques[t], key=lambda m: m["id"]))
        rows.append(f'<tr><td><a href="https://attack.mitre.org/techniques/{t.replace(".", "/")}/">{t}</a></td><td>{links}</td></tr>')
    parts.append('<section class="page"><h2 id="attack-index">Appendix · ATT&amp;CK technique index</h2>'
                 '<table class="compact"><thead><tr><th>Technique</th><th>Playbooks</th></tr></thead><tbody>'
                 + "".join(rows) + "</tbody></table></section>")
    parts.append(f"""
<section class="page closing">
  <h2>About</h2>
  <p>The SOC IR Field Guide is generated from the open-source <strong>soc-triage-playbooks</strong> repository. Every query in it is compiled against the Microsoft Sentinel schemas in CI, and every linked detection is checked to exist.</p>
  <table><tbody>
  <tr><td>Playbooks (source)</td><td><a href="https://github.com/rizwancyberlock-svg/soc-triage-playbooks">github.com/rizwancyberlock-svg/soc-triage-playbooks</a></td></tr>
  <tr><td>Google SecOps detections</td><td><a href="https://github.com/rizwancyberlock-svg/open-yaral-detections">github.com/rizwancyberlock-svg/open-yaral-detections</a></td></tr>
  <tr><td>Microsoft Sentinel detections</td><td><a href="https://github.com/rizwancyberlock-svg/sentinel-kql-detections">github.com/rizwancyberlock-svg/sentinel-kql-detections</a></td></tr>
  <tr><td>Log-source onboarding</td><td><a href="https://github.com/rizwancyberlock-svg/siem-onboarding-kit">github.com/rizwancyberlock-svg/siem-onboarding-kit</a></td></tr>
  <tr><td>Author</td><td>Rizwan Ahmed · <a href="https://www.linkedin.com/in/rizwan-ahmed-cdc/">linkedin.com/in/rizwan-ahmed-cdc</a></td></tr>
  </tbody></table>
  <p class="note">Licensed under the MIT License. Product names are trademarks of their respective owners.</p>
</section>""")
    return TEMPLATE.replace("{{BODY}}", "\n".join(parts)).replace("{{MERMAID}}", MERMAID).replace("{{VERSION}}", version)


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="SOC IR Field Guide by Rizwan Ahmed: 60 decision-tree playbooks for Google SecOps and Microsoft Sentinel.">
<title>SOC IR Field Guide - Rizwan Ahmed</title>
<style>
@page { size: A4; margin: 16mm 15mm 18mm 15mm;
  @bottom-left { content: "SOC IR Field Guide · Rizwan Ahmed"; font: 8pt "Segoe UI", Arial, sans-serif; color: #7a8699; }
  @bottom-right { content: counter(page); font: 8pt "Segoe UI", Arial, sans-serif; color: #7a8699; } }
@page :first { margin: 0; @bottom-left { content: none; } @bottom-right { content: none; } }
:root { --ink:#132033; --muted:#5b6b82; --line:#d9e0ea; --accent:#0b62c4; --soft:#eef4fb; --code:#0f1b2d; }
* { box-sizing: border-box; }
body { font: 10pt/1.5 "Segoe UI", "Inter", Arial, sans-serif; color: var(--ink); margin: 0; }
a { color: var(--accent); text-decoration: none; }
h1,h2,h3,h4 { line-height: 1.2; margin: 0 0 6pt; }
h2 { font-size: 17pt; } h3 { font-size: 12pt; margin-top: 12pt; color: var(--accent); border-bottom: 1px solid var(--line); padding-bottom: 3pt; }
h4 { font-size: 10.5pt; margin-top: 8pt; }
p { margin: 4pt 0 6pt; }
section.page { break-before: page; }
.cover { height: 296mm; display: flex; flex-direction: column; justify-content: center; padding: 0 24mm;
  background: linear-gradient(160deg, #0b1f3a 0%, #0b62c4 140%); color: #fff; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
html, body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.cover .kicker, .divider .kicker { letter-spacing: .18em; text-transform: uppercase; font-size: 9pt; font-weight: 700; color: #8cc4ff; }
.cover h1 { font-size: 46pt; margin: 10pt 0; letter-spacing: -.02em; }
.cover .sub { font-size: 13pt; max-width: 140mm; color: #d6e6fa; }
.cover .stats { display: flex; gap: 10pt; margin: 24pt 0; }
.cover .stats div { background: rgba(255,255,255,.1); border: 1px solid rgba(255,255,255,.25); border-radius: 8pt; padding: 10pt 12pt; min-width: 34mm; }
.cover .stats b { display: block; font-size: 22pt; } .cover .stats span { font-size: 8.5pt; color: #cfe2fb; }
.cover .author { margin-top: 30pt; font-size: 11pt; } .cover .author span { font-size: 8.5pt; color: #b9d4f5; }
.divider { break-before: page; height: 240mm; display: flex; flex-direction: column; justify-content: center; padding-left: 10mm; border-left: 6pt solid var(--accent); }
.divider h1 { font-size: 38pt; } .divider .kicker { color: var(--accent); } .divider p { font-size: 13pt; color: var(--muted); }
.toc h3 { margin-top: 10pt; } .toc-list { margin: 2pt 0 6pt; padding-left: 16pt; } .toc-list li { margin: 1.5pt 0; }
.toc-area h4 { margin: 8pt 0 2pt; } .toc ul.toc-list { list-style: none; padding-left: 4pt; columns: 1; }
.pid { font-family: Consolas, monospace; font-size: 8.5pt; color: var(--muted); }
.sev { display: inline-block; font-size: 7.5pt; font-weight: 700; padding: 1pt 6pt; border-radius: 8pt; color: #fff; vertical-align: middle; }
.sev.critical { background: #b42318; } .sev.high { background: #d9480f; } .sev.medium { background: #b7791f; } .sev.low { background: #2f855a; }
.tech { display: inline-block; font: 7.5pt Consolas, monospace; background: var(--soft); border: 1px solid var(--line); border-radius: 6pt; padding: 1pt 5pt; margin-left: 4pt; }
.pb-head { border-bottom: 2pt solid var(--accent); padding-bottom: 6pt; margin-bottom: 8pt; }
.pb-area { font-size: 8.5pt; text-transform: uppercase; letter-spacing: .1em; color: var(--accent); font-weight: 700; }
.pb-head h2 { font-size: 19pt; margin: 3pt 0 5pt; }
blockquote { margin: 6pt 0 8pt; padding: 7pt 10pt; background: var(--soft); border-left: 4pt solid var(--accent); border-radius: 0 6pt 6pt 0; }
table { width: 100%; border-collapse: collapse; margin: 6pt 0 8pt; font-size: 8.8pt; break-inside: auto; }
th { background: #13325b; color: #fff; text-align: left; padding: 4pt 6pt; }
td { border-bottom: 1px solid var(--line); padding: 4pt 6pt; vertical-align: top; }
tr { break-inside: avoid; }
table.compact td { padding: 2pt 6pt; }
code { font-family: Consolas, "Cascadia Code", monospace; font-size: 8.4pt; background: #f1f4f9; padding: 0 2pt; border-radius: 3pt; }
.code { margin: 4pt 0 8pt; } .code .lang { break-after: avoid; } .code pre { orphans: 4; widows: 4; }
.code .lang { display: inline-block; font-size: 7pt; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: #fff; background: #36506f; padding: 1pt 6pt; border-radius: 4pt 4pt 0 0; }
.code pre { margin: 0; background: var(--code); color: #dbe7f7; padding: 7pt 9pt; border-radius: 0 6pt 6pt 6pt; font: 7.8pt/1.45 Consolas, "Cascadia Code", monospace; white-space: pre-wrap; word-break: break-word; }
.tree { margin: 4pt 0 8pt; padding: 6pt; border: 1px solid var(--line); border-radius: 8pt; text-align: center; break-inside: avoid; }
.tree svg { max-width: 100% !important; width: auto !important; max-height: 86mm; height: auto; }
ul, ol { margin: 3pt 0 6pt; padding-left: 16pt; } li { margin: 2pt 0; }
.back { text-align: right; font-size: 8pt; margin-top: 6pt; }
.note { font-size: 8.5pt; color: var(--muted); border-top: 1px solid var(--line); padding-top: 6pt; }
.fw h2 { color: var(--ink); }
.topbar { display: none; }
@media screen {
  html { scroll-behavior: smooth; scroll-padding-top: 64px; }
  body { background: #e8edf4; font-size: 15px; }
  section.page, section.divider, section.cover { max-width: 210mm; margin: 22px auto; background: #fff; padding: 15mm 15mm 12mm;
    border-radius: 10px; box-shadow: 0 2px 14px rgba(19,32,51,.10); }
  section.cover { min-height: 250mm; height: auto; margin-top: 76px; background: linear-gradient(160deg, #0b1f3a 0%, #0b62c4 140%); }
  section.divider { height: auto; min-height: 90mm; border-left: 8px solid var(--accent); }
  .topbar { display: flex; position: fixed; top: 0; left: 0; right: 0; z-index: 10; gap: 18px; align-items: center; padding: 12px 22px;
    background: #0b1f3a; color: #fff; font-size: 14px; box-shadow: 0 2px 10px rgba(0,0,0,.25); }
  .topbar b { margin-right: auto; } .topbar a { color: #8cc4ff; }
  @media (max-width: 820px) { section.page, section.divider, section.cover { margin: 12px 8px; padding: 18px 16px; }
    section.cover { margin-top: 64px; min-height: 0; padding: 40px 20px; } .cover .stats { flex-wrap: wrap; } .cover .stats div { min-width: 40%; }
    table { display: block; overflow-x: auto; } .tree { overflow-x: auto; text-align: left; } .tree svg { min-width: 520px; max-height: none; }
    .pb-head h2 { font-size: 22px; } .topbar { gap: 12px; padding: 10px 12px; font-size: 13px; } .cover h1 { font-size: 40px; } .topbar a.hide-sm { display: none; } }
}
</style>
<script src="{{MERMAID}}"></script>
</head><body>
<nav class="topbar"><b>🧭 SOC IR Field Guide</b><a href="#contents">Contents</a><a class="hide-sm" href="#attack-index">ATT&amp;CK index</a>
<a href="https://github.com/rizwancyberlock-svg/soc-triage-playbooks/releases/latest">⬇ PDF</a><a class="hide-sm" href="https://github.com/rizwancyberlock-svg/soc-triage-playbooks">GitHub</a></nav>
{{BODY}}
<script>
  mermaid.initialize({ startOnLoad: false, theme: "neutral", securityLevel: "strict",
    flowchart: { htmlLabels: true, curve: "basis", useMaxWidth: true }, fontFamily: "Segoe UI, Arial, sans-serif" });
  mermaid.run({ querySelector: "pre.mermaid" }).then(() => {
    const bad = [...document.querySelectorAll(".tree")].filter(t => !t.querySelector("svg") || /Syntax error/i.test(t.textContent));
    document.body.setAttribute("data-mermaid", bad.length ? "error:" + bad.length : "ok");
  }).catch(e => document.body.setAttribute("data-mermaid", "error:" + e));
</script>
</body></html>
"""


def find_chrome(explicit: str | None) -> str:
    cands = [explicit] if explicit else []
    cands += [shutil.which(n) for n in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome")]
    cands += [r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    for c in cands:
        if c and Path(c).exists():
            return c
    raise SystemExit("Chrome / Chromium not found - pass --chrome")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True, help="HTML output path")
    ap.add_argument("--pdf", type=Path, help="also print a PDF with headless Chrome")
    ap.add_argument("--chrome", help="path to Chrome / Chromium")
    ap.add_argument("--version", default=dt.date.today().strftime("%Y.%m"))
    args = ap.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build(args.version), encoding="utf-8", newline="\n")
    print(f"wrote {args.out}")
    if not args.pdf:
        return 0
    chrome = find_chrome(args.chrome)
    url = args.out.resolve().as_uri()
    base = [chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--run-all-compositor-stages-before-draw",
            "--virtual-time-budget=60000"]
    with tempfile.TemporaryDirectory() as profile:
        dom = subprocess.run(base + [f"--user-data-dir={profile}", "--dump-dom", url], capture_output=True, text=True,
                             encoding="utf-8", timeout=300).stdout
        state = re.search(r'data-mermaid="([^"]+)"', dom)
        if not state or state.group(1) != "ok":
            print(f"ERROR  decision trees did not render: {state.group(1) if state else 'mermaid did not run'}")
            return 1
        print(f"rendered {dom.count('<svg')} diagrams")
        args.pdf.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(base + [f"--user-data-dir={profile}", "--no-pdf-header-footer", f"--print-to-pdf={args.pdf.resolve()}", url],
                       check=True, capture_output=True, timeout=300)
    print(f"wrote {args.pdf} ({args.pdf.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
