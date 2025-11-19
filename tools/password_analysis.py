#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
password_analysis.py

Estimate brute-force times and generate charts for JuMan password configurations.
Produces:
 - PNG bar chart showing estimated cracking times (log scale) for sample passwords
   across different attacker capabilities and KDF iteration settings.
 - PNG pie chart breaking down relative difficulty.
 - Markdown report explaining calculations in Bahasa Indonesia.

Usage:
  python password_analysis.py --output tools/password_analysis_out

Notes:
 - Estimates are heuristic and meant for illustrative/journal use only.
 - The model uses a simple relation: attacker_attempts_per_second = raw_ops_per_second / kdf_iterations
   where raw_ops_per_second is the attacker's HMAC (or equivalent) ops/sec capability.
"""

from pathlib import Path
import math
import json
import argparse
import matplotlib.pyplot as plt

OUT_DEFAULT = Path('tools/password_analysis_out')

# sample passwords to evaluate
SAMPLE_PASSWORDS = [
    ('admin', 'common weak'),
    ('123456', 'common weak'),
    ('password', 'common weak'),
    ('JuMan123', 'moderate'),
    ('G7!x9PqZ', 'random 8 chars'),
]

# sample alphabets for brute-force full-space estimates
ALPHABETS = {
    'digits': 10,
    'lower': 26,
    'lower+digits': 36,
    'alnum+symbols': 94
}

# attacker raw HMAC-like ops/sec assumptions (representative samples)
ATTACKER_RAW_OPS = {
    'Laptop-CPU': 1e7,      # raw ops/sec
    'Single-GPU': 1e9,
    'GPU-Cluster (8x)': 8e9,
    'ASIC/Cloud': 1e11
}

# KDF iterations scenarios to compare (Java current / suggested)
KDF_SCENARIOS = {
    'Java-default (65536)': 65536,
    'Recommended (200000)': 200000
}


def estimates_for_password(password, iterations, raw_ops):
    """Return expected time to find this specific password (average) in seconds using brute-force searching entire keyspace
    For a given password we approximate its equivalent keyspace size by its entropy (Shannon) using character classes.
    """
    # estimate entropy per character by detected classes
    classes = 0
    if any(c.islower() for c in password): classes += 26
    if any(c.isupper() for c in password): classes += 26
    if any(c.isdigit() for c in password): classes += 10
    # symbols approximate
    if any((not c.isalnum()) for c in password): classes += 32
    if classes == 0:
        classes = 26
    # approximate keyspace size
    keyspace = classes ** len(password)
    # attacker attempts per second adjusted for KDF iterations
    attempts_per_sec = raw_ops / iterations
    # average attempts to find password (assuming random position) = keyspace/2
    avg_seconds = keyspace / 2.0 / attempts_per_sec
    worst_seconds = keyspace / attempts_per_sec
    return {
        'password': password,
        'length': len(password),
        'classes': classes,
        'keyspace': keyspace,
        'attempts_per_sec': attempts_per_sec,
        'avg_seconds': avg_seconds,
        'worst_seconds': worst_seconds
    }


def human_time(seconds):
    if seconds < 1:
        return f"{seconds*1000:.2f} ms"
    mins, sec = divmod(seconds, 60)
    hours, mins = divmod(mins, 60)
    days, hours = divmod(hours, 24)
    years, days = divmod(days, 365)
    s = []
    if years: s.append(f"{int(years)}y")
    if days: s.append(f"{int(days)}d")
    if hours: s.append(f"{int(hours)}h")
    if mins: s.append(f"{int(mins)}m")
    if sec and not s: s.append(f"{int(sec)}s")
    if not s:
        return f"{seconds:.2f} s"
    return ' '.join(s)


def generate_charts(outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    results = {}
    # iterate scenarios
    for kdf_name, iterations in KDF_SCENARIOS.items():
        results[kdf_name] = {}
        for atk_name, raw_ops in ATTACKER_RAW_OPS.items():
            res_list = []
            for pwd, label in SAMPLE_PASSWORDS:
                est = estimates_for_password(pwd, iterations, raw_ops)
                res_list.append(est)
            results[kdf_name][atk_name] = res_list

    # create bar charts per KDF comparing attackers for sample passwords
    for kdf_name in results:
        fig, ax = plt.subplots(figsize=(10,6))
        labels = [p[0] for p in SAMPLE_PASSWORDS]
        x = range(len(labels))
        width = 0.18
        for i, (atk_name, v) in enumerate(results[kdf_name].items()):
            times = [max(1, r['avg_seconds']) for r in v]
            # plot on log scale
            ax.bar([xi + i*width for xi in x], times, width=width, label=atk_name)
        ax.set_yscale('log')
        ax.set_xticks([xi + width for xi in x])
        ax.set_xticklabels(labels)
        ax.set_ylabel('Estimated average crack time (seconds, log scale)')
        ax.set_title(f'Password cracking time estimates — {kdf_name}')
        ax.legend()
        fig_path = outdir / f'password_crack_times_{kdf_name.replace(" ","_")}.png'
        plt.tight_layout()
        plt.savefig(fig_path, dpi=150)
        plt.close()

    # pie chart example: distribution of keyspace difficulty for a chosen scenario
    # pick Recommended (200000) & Single-GPU
    scenario = results['Recommended (200000)']['Single-GPU']
    sizes = [s['keyspace'] for s in scenario]
    # normalize to sum 1 for pie
    total = sum(sizes)
    if total == 0: total = 1
    labels = [f"{r['password']}" for r in scenario]
    fig, ax = plt.subplots(figsize=(6,6))
    ax.pie([s/total for s in sizes], labels=labels, autopct='%1.1f%%')
    ax.set_title('Relative keyspace size for sample passwords (Recommended KDF, Single-GPU)')
    pie_path = outdir / 'password_keyspace_pie.png'
    plt.savefig(pie_path, dpi=150)
    plt.close()

    # write JSON + markdown report
    report = {'scenarios': results}
    (outdir / 'password_analysis.json').write_text(json.dumps(report, indent=2))

    # generate markdown
    md = []
    md.append('# Password Analysis Report (JuMan)')
    md.append('Hasil estimasi waktu brute-force untuk contoh password menggunakan model sederhana. Nilai adalah perkiraan. Lihat PNG untuk diagram.')
    md.append('')
    for kdf_name, atk_map in results.items():
        md.append(f'## KDF scenario: {kdf_name} (iterations={KDF_SCENARIOS[kdf_name]})')
        for atk_name, entries in atk_map.items():
            md.append(f'### Attacker: {atk_name} (raw ops/sec ~ {ATTACKER_RAW_OPS[atk_name]:.0f})')
            md.append('|password|length|classes|keyspace|attempts/sec|avg time|worst time|')
            md.append('|---|---:|---:|---:|---:|---:|---:|')
            for e in entries:
                md.append(f"|{e['password']}|{e['length']}|{e['classes']}|{int(e['keyspace'])}|{e['attempts_per_sec']:.2f}|{human_time(e['avg_seconds'])}|{human_time(e['worst_seconds'])}|")
            md.append('')
    md.append('## Charts')
    for p in outdir.iterdir():
        if p.suffix.lower() in ('.png',):
            md.append(f'![]({p.name})')
    out_md = outdir / 'password_analysis_report.md'
    out_md.write_text('\n'.join(md), encoding='utf-8')
    print('Wrote password analysis to', outdir)
    return outdir


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output', default=str(OUT_DEFAULT))
    args = p.parse_args()
    generate_charts(Path(args.output))
