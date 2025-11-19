#!/usr/bin/env python3
"""
analyze_backup.py

Analyze a single JuMan backup file and produce:
 - JSON report about format, contents, and security properties
 - PNG diagrams: (1) attack surface flow, (2) brute-force time estimates
 - an HTML summary that embeds diagrams

Usage:
    python analyze_backup.py --backup /path/to/juman_backup_....jumanbackup --repo-root .. --out out_dir

Dependencies:
    pip install matplotlib jinja2

Note: This script makes conservative, heuristic assessments and does not
attempt to decrypt files or perform attacks.
"""

import argparse
import json
import sys
from pathlib import Path
import zipfile
import struct
import math
import os
import re

try:
    import matplotlib.pyplot as plt
    from jinja2 import Template
except Exception:
    print("Missing dependency: pip install matplotlib jinja2")
    sys.exit(1)

BACKUP_MAGIC = b'JMNB'  # recommended signed backup magic (may not be present)


def detect_format(path: Path):
    with path.open('rb') as f:
        h = f.read(8)
    if h.startswith(b'PK'):
        return 'zip'
    if h.startswith(BACKUP_MAGIC):
        return 'signed-backup'
    # heuristic: many encrypted blobs are binary; check for printable
    non_print = sum(1 for b in h if b < 9 or (b > 13 and b < 32))
    if non_print / max(1, len(h)) > 0.2:
        return 'binary-encrypted'
    return 'unknown'


def inspect_zip(path: Path):
    info = {'entries': []}
    try:
        with zipfile.ZipFile(path, 'r') as z:
            info['entries'] = z.namelist()
            info['contains_master_key'] = any('master.key' in n for n in z.namelist())
            info['contains_master_key_enc'] = any('master.key.enc' in n for n in z.namelist())
            info['comment'] = z.comment.decode('utf-8', errors='ignore') if z.comment else ''
    except Exception as e:
        info['error'] = str(e)
    return info


def inspect_signed_backup(path: Path):
    # parse our signed format: magic(4) version(1) taglen(4) tag... rest(zip)
    info = {}
    try:
        with path.open('rb') as f:
            magic = f.read(4)
            if magic != BACKUP_MAGIC:
                return {'error': 'bad-magic'}
            version = f.read(1)[0]
            tag_len = struct.unpack('>I', f.read(4))[0]
            tag = f.read(tag_len)
            info.update({'version': version, 'tag_len': tag_len})
            # Rest is zip bytes; write to temp file and inspect
            rest = f.read()
            # try to find zip header inside rest
            idx = rest.find(b'PK')
            if idx != -1:
                # write temp
                import tempfile
                tf = tempfile.NamedTemporaryFile(delete=False)
                try:
                    tf.write(rest[idx:])
                    tf.close()
                    zi = inspect_zip(Path(tf.name))
                    info['zip_inspect'] = zi
                finally:
                    os.unlink(tf.name)
            else:
                info['zip_inspect'] = {'found': False}
    except Exception as e:
        info['error'] = str(e)
    return info


def analyze_password_crack_time(iterations, attacker_hash_per_second, password_entropy_bits):
    # For PBKDF2, cost scales with iterations; estimate guesses/sec = attacker_hash_per_second / iterations
    if iterations <= 0:
        iterations = 1
    guesses_per_sec = attacker_hash_per_second / iterations
    # number of guesses to exhaust search space of given entropy = 2^entropy
    total = 2 ** password_entropy_bits
    seconds = total / guesses_per_sec
    return seconds


def human_duration(seconds):
    if seconds < 1:
        return f"{seconds:.3f} s"
    intervals = [
        ('year', 365*24*3600),
        ('day', 24*3600),
        ('hour', 3600),
        ('minute', 60),
        ('second', 1),
    ]
    parts = []
    remainder = int(seconds)
    for name, sec in intervals:
        if remainder >= sec:
            val = remainder // sec
            remainder = remainder % sec
            parts.append(f"{val} {name}{'s' if val>1 else ''}")
    if not parts:
        return f"{seconds:.2f} s"
    return ', '.join(parts[:3])


def make_bruteforce_chart(iterations, out_png: Path):
    # attacker rates (hash evaluations per second without KDF cost): optimistic to strong
    raw_rates = [1e3, 1e5, 1e7, 1e9]  # guesses/sec before KDF cost
    # passwords entropy examples: 20 (weak), 40 (moderate), 60 (strong), 80 (very strong)
    entropies = [20, 40, 60, 80]
    data = []
    for e in entropies:
        times = [analyze_password_crack_time(iterations, r, e) for r in raw_rates]
        data.append(times)
    # plot grouped bar chart
    import numpy as np
    labels = ['1e3','1e5','1e7','1e9']
    x = np.arange(len(labels))
    width = 0.2
    plt.figure(figsize=(9,4))
    for i, e in enumerate(entropies):
        ys = [t/ (3600*24*365) for t in data[i]]  # years
        plt.bar(x + (i-1.5)*width, ys, width=width, label=f'{e} bits')
    plt.ylabel('Years to exhaust keyspace (log scale)')
    plt.yscale('log')
    plt.xticks(x, labels)
    plt.xlabel('Attacker raw hashes/sec (before KDF cost)')
    plt.title(f'Estimated brute-force time (PBKDF2 iterations={iterations})')
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()
    return str(out_png)


def draw_attack_surface(out_png: Path, findings: dict):
    # Simple box diagram using matplotlib
    plt.figure(figsize=(8,4))
    ax = plt.gca()
    ax.axis('off')
    # boxes positions
    boxes = {
        'attacker': (0.1,0.6,0.2,0.25),
        'backup': (0.4,0.5,0.3,0.35),
        'master_key': (0.75,0.7,0.2,0.2),
        'kdf': (0.75,0.4,0.2,0.2),
    }
    def draw_box(x,y,w,h,label):
        rect = plt.Rectangle((x,y), w, h, fill=True, color='#f0f0f0', ec='black')
        ax.add_patch(rect)
        ax.text(x+w/2, y+h/2, label, ha='center', va='center')
    draw_box(*boxes['attacker'],'Attacker')
    draw_box(*boxes['backup'],'Backup File')
    draw_box(*boxes['master_key'],'Master Key
(if included)')
    draw_box(*boxes['kdf'],'KDF / Password')
    # arrows
    def arrow(a,b):
        (x1,y1,w1,h1) = boxes[a]
        (x2,y2,w2,h2) = boxes[b]
        xstart = x1 + w1
        ystart = y1 + h1/2
        xend = x2
        yend = y2 + h2/2
        ax.annotate('', xy=(xend,yend), xytext=(xstart, ystart), arrowprops=dict(arrowstyle="->"))
    arrow('attacker','backup')
    arrow('backup','master_key')
    arrow('backup','kdf')
    title = 'Attack surface: Backup compromise'
    plt.title(title)
    plt.savefig(out_png)
    plt.close()
    return str(out_png)


HTML_TMPL = """
<html><body>
<h1>JuMan Backup Analysis</h1>
<p>File: {{ file }}</p>
<h2>Findings</h2>
<ul>
{% for k,v in findings.items() %}
  <li><b>{{k}}</b>: {{v}}</li>
{% endfor %}
</ul>
<h2>Diagrams</h2>
<p><img src="{{ attack_png }}" width="700"></p>
<p><img src="{{ brute_png }}" width="700"></p>
</body></html>
"""


def analyze(backup_path: Path, repo_root: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = {}
    fmt = detect_format(backup_path)
    findings['detected_format'] = fmt
    if fmt == 'zip':
        zi = inspect_zip(backup_path)
        findings.update(zi)
    elif fmt == 'signed-backup':
        si = inspect_signed_backup(backup_path)
        findings.update(si)
    elif fmt == 'binary-encrypted':
        findings['note'] = 'File looks like encrypted binary data (non-printable bytes)'
    else:
        findings['note'] = 'Unknown format'

    # KDF extract
    am = None
    for p in repo_root.rglob('AuthManager.java'):
        am = p
        break
    if am:
        text = am.read_text(encoding='utf-8', errors='ignore')
        m = re.search(r'PBKDF2_ITER\s*=\s*(\d+)', text)
        if m:
            findings['pbkdf2_iterations'] = int(m.group(1))
        else:
            m2 = re.search(r'PBEKeySpec\([^,]+,\s*[^,]+,\s*(\d+)\s*,', text)
            if m2:
                findings['pbkdf2_iterations'] = int(m2.group(1))
    else:
        findings['pbkdf2_source'] = 'AuthManager.java not found'

    # brute force diagram: choose iterations value
    iters = findings.get('pbkdf2_iterations', 65536)
    brute_png = Path(out_dir) / 'bruteforce_estimates.png'
    make_bruteforce_chart(iters, brute_png)
    attack_png = Path(out_dir) / 'attack_surface.png'
    draw_attack_surface(attack_png, findings)

    # write html report
    tmpl = Template(HTML_TMPL)
    html = tmpl.render(file=str(backup_path), findings=findings, attack_png=str(attack_png), brute_png=str(brute_png))
    html_path = out_dir / 'backup_analysis.html'
    with html_path.open('w', encoding='utf-8') as f:
        f.write(html)
    # json
    with (out_dir / 'backup_analysis.json').open('w', encoding='utf-8') as jf:
        json.dump(findings, jf, indent=2)
    return html_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--backup', '-b', required=True, help='Path to backup file to analyze')
    parser.add_argument('--repo-root', '-r', default='.', help='Repo root to find AuthManager.java')
    parser.add_argument('--out', '-o', default='tools/backup_analysis_out', help='Output dir')
    args = parser.parse_args()
    bp = Path(args.backup)
    if not bp.exists():
        print('Backup not found:', bp)
        sys.exit(1)
    out = analyze(bp, Path(args.repo_root), Path(args.out))
    print('Report written:', out)
