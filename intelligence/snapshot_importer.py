"""intelligence/snapshot_importer.py
--------------------------------
Parser for VSCode browser view snapshots (the format produced by the shared page read).
Provides `parse_vscode_snapshot_text(text, query)` which returns normalized result dicts
with keys: target, dataset, source, url, snippet, line_number, line, confidence.

Also includes a small CLI for ad-hoc runs.
"""
from __future__ import annotations

import re
from typing import List


def _guess_dataset_from_heading(heading: str | None) -> str:
    if not heading:
        return "External API"
    h = heading.lower()
    if 'breach' in h or 'security' in h:
        return 'Security Breaches'
    if 'stolen' in h or 'malware' in h:
        return 'Stolen Information'
    if 'gaming' in h or 'steam' in h or 'roblox' in h or 'minecraft' in h:
        return 'Gaming Profiles'
    if 'signup' in h or 'website' in h:
        return 'Website Signups'
    return heading


def parse_vscode_snapshot_text(text: str, query: str) -> List[dict]:
    lines = text.splitlines()
    results: List[dict] = []

    for i, l in enumerate(lines):
        if '/url:' not in l:
            continue
        m = re.search(r'/url:\s*(\S+)', l)
        if not m:
            continue
        url = m.group(1).strip()

        # look back up to 12 lines for heading
        heading = None
        for j in range(max(0, i-12), i+1):
            mh = re.search(r'heading\s+"([^"]+)"', lines[j])
            if mh:
                heading = mh.group(1).strip()
                break

        # look forward for a short descriptive text or 'text:' entries
        snippet = None
        for j in range(i, min(len(lines), i+8)):
            mt = re.search(r'text:\s*(.*)', lines[j])
            if mt:
                s = mt.group(1).strip()
                if s:
                    snippet = s
                    break
        # fallback: try to capture nearby 'paragraph' or generic labels
        if not snippet:
            for j in range(i-2, min(len(lines), i+6)):
                if 'paragraph' in lines[j] or 'generic' in lines[j]:
                    # take next line as possible snippet
                    if j+1 < len(lines):
                        cand = lines[j+1].strip()
                        if cand and len(cand) < 200:
                            snippet = cand
                            break

        dataset = _guess_dataset_from_heading(heading)

        # Only include items that mention query or look like profiles/registrations
        combined = (heading or '') + ' ' + (snippet or '') + ' ' + url
        if query.lower() in combined.lower() or re.search(r'profile|signup|register|view|steam|roblox|minecraft|paste|breach|credential', combined, re.I):
            results.append({
                'target': query,
                'dataset': dataset,
                'source': 'Snapshot import',
                'url': url,
                'snippet': (snippet or '')[:800],
                'line_number': None,
                'line': (snippet or ''),
                'confidence': 'medium',
            })

    return results


if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 3:
        print('Usage: python snapshot_importer.py <snapshot_file> <query>')
        raise SystemExit(1)

    path = sys.argv[1]
    q = sys.argv[2]
    txt = open(path, 'r', encoding='utf-8', errors='ignore').read()
    out = parse_vscode_snapshot_text(txt, q)
    print(json.dumps(out, ensure_ascii=False, indent=2))
