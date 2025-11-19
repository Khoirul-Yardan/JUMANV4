#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_security_diagrams.py

Generate security diagrams for JuMan:
- Application security (components & trust boundaries)
- File encryption flow (how files are encrypted, where keys live)
- Backup security (what backup contains and protections)

For each area the script produces two diagrams: current (based on repo state)
and recommended (hardened configuration). Saves PNG files and a markdown
report comparing current vs recommended details.

Usage:
  python generate_security_diagrams.py --output tools/security_diagrams_out

Requires: matplotlib, networkx
"""

import argparse
from pathlib import Path
import matplotlib.pyplot as plt
import networkx as nx
import json
import shutil

# try to import analyzer from existing audit script
try:
    from juman_audit_full import analyze
except Exception:
    analyze = None

OUT_DIR_DEFAULT = Path('tools/security_diagrams_out')


def draw_graph(nodes, edges, title, out_png: Path):
    G = nx.DiGraph()
    for n, attr in nodes.items():
        G.add_node(n, **attr)
    for a, b, attr in edges:
        G.add_edge(a, b, **(attr or {}))

    plt.figure(figsize=(8,5))
    pos = nx.spring_layout(G, seed=42)

    # node colors by role
    colors = []
    sizes = []
    labels = {}
    for n, attr in G.nodes(data=True):
        role = attr.get('role','other')
        if role == 'user': colors.append('#7fbfff')
        elif role == 'app': colors.append('#88c0d0')
        elif role == 'storage': colors.append('#ffdf7f')
        elif role == 'key': colors.append('#ff7f7f')
        elif role == 'backup': colors.append('#bfffbf')
        else: colors.append('#dddddd')
        sizes.append(attr.get('size', 1200))
        label = n
        if attr.get('note'): label = f"{n}\n({attr.get('note')})"
        labels[n] = label

    nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=sizes)
    nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=12)
    nx.draw_networkx_labels(G, pos, labels, font_size=8)
    plt.title(title)
    plt.axis('off')
    out_png.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_png, bbox_inches='tight', dpi=150)
    plt.close()
    return out_png


def make_app_diagrams(report, outdir: Path):
    cur_nodes = {
        'User (UI)': {'role':'user'},
        'JuMan App': {'role':'app'},
        'Storage (storage/)': {'role':'storage'},
        'master.key (plain?)': {'role':'key', 'note': 'present' if report.get('master_key_enc')==False else 'encrypted'},
        'recovery.txt': {'role':'key', 'note': 'present' if report.get('recovery') else 'missing'}
    }
    cur_edges = [
        ('User (UI)', 'JuMan App', None),
        ('JuMan App', 'Storage (storage/)', None),
        ('JuMan App', 'master.key (plain?)', None),
        ('JuMan App', 'recovery.txt', None)
    ]
    rec_nodes = {
        'User (UI)': {'role':'user'},
        'JuMan App': {'role':'app'},
        'Storage (storage/)': {'role':'storage', 'note':'encrypted-at-rest'},
        'master.key.enc (encrypted)': {'role':'key', 'note':'protected by password/OS keystore'},
        'recovery (offline)': {'role':'key', 'note':'stored offline'}
    }
    rec_edges = [
        ('User (UI)', 'JuMan App', None),
        ('JuMan App', 'Storage (storage/)', None),
        ('JuMan App', 'master.key.enc (encrypted)', None),
        ('JuMan App', 'recovery (offline)', None)
    ]

    cur_png = draw_graph(cur_nodes, cur_edges, 'App Security - Current', outdir / 'app_security_current.png')
    rec_png = draw_graph(rec_nodes, rec_edges, 'App Security - Recommended', outdir / 'app_security_recommended.png')
    return cur_png, rec_png


def make_file_encryption_diagrams(report, outdir: Path):
    cur_nodes = {
        'File (original)': {'role':'user'},
        'CryptoService (AES-GCM)': {'role':'app', 'note':'AES-GCM, IV12B, tag128'},
        'Encrypted file (.jmn)': {'role':'storage', 'note':'ciphertext||tag'},
        'master.key (plain?)': {'role':'key', 'note':'present' if report.get('master_key_enc')==False else 'encrypted'}
    }
    cur_edges = [
        ('File (original)', 'CryptoService (AES-GCM)', None),
        ('CryptoService (AES-GCM)', 'Encrypted file (.jmn)', None),
        ('CryptoService (AES-GCM)', 'master.key (plain?)', None)
    ]

    rec_nodes = {
        'File (original)': {'role':'user'},
        'CryptoService (AES-GCM)': {'role':'app', 'note':'AES-GCM + header+meta'},
        'Encrypted file (.jmn)': {'role':'storage', 'note':'magic||meta||iv||ciphertext||tag'},
        'master.key.enc (encrypted)': {'role':'key', 'note':'KDF-protected or OS keystore'},
        'HMAC/Signature (backup/file)': {'role':'backup', 'note':'optional signature for integrity'}
    }
    rec_edges = [
        ('File (original)', 'CryptoService (AES-GCM)', None),
        ('CryptoService (AES-GCM)', 'Encrypted file (.jmn)', None),
        ('CryptoService (AES-GCM)', 'master.key.enc (encrypted)', None),
        ('Encrypted file (.jmn)', 'HMAC/Signature (backup/file)', None)
    ]

    cur_png = draw_graph(cur_nodes, cur_edges, 'File Encryption - Current', outdir / 'file_encryption_current.png')
    rec_png = draw_graph(rec_nodes, rec_edges, 'File Encryption - Recommended', outdir / 'file_encryption_recommended.png')
    return cur_png, rec_png


def make_backup_diagrams(report, outdir: Path):
    cur_nodes = {
        'storage/': {'role':'storage'},
        'ZIP (raw)': {'role':'app'},
        'Encrypted backup (.jumanbackup)': {'role':'backup', 'note':'zip encrypted by AES-GCM'},
        'master.key (maybe included?)': {'role':'key', 'note':'present' if report.get('master_key_enc')==False else 'excluded/enc'}
    }
    cur_edges = [
        ('storage/', 'ZIP (raw)', None),
        ('ZIP (raw)', 'Encrypted backup (.jumanbackup)', None),
        ('ZIP (raw)', 'master.key (maybe included?)', None)
    ]

    rec_nodes = {
        'storage/': {'role':'storage', 'note':'encrypted at rest'},
        'ZIP (raw)': {'role':'app', 'note':'created without master.key'},
        'Encrypted backup (.jumanbackup)': {'role':'backup', 'note':'AES-GCM + HMAC/signature'},
        'master.key.enc (separate secure)': {'role':'key', 'note':'store offline or keystore'}
    }
    rec_edges = [
        ('storage/', 'ZIP (raw)', None),
        ('ZIP (raw)', 'Encrypted backup (.jumanbackup)', None),
        ('ZIP (raw)', 'master.key.enc (separate secure)', None)
    ]

    cur_png = draw_graph(cur_nodes, cur_edges, 'Backup Security - Current', outdir / 'backup_security_current.png')
    rec_png = draw_graph(rec_nodes, rec_edges, 'Backup Security - Recommended', outdir / 'backup_security_recommended.png')
    return cur_png, rec_png


def generate_comparison_md(report, outdir: Path):
    md = []
    md.append('# JuMan Security Diagrams & Comparison')
    md.append('Generated automatically')
    md.append('')

    md.append('## Summary Risk Scores (heuristic)')
    # simple heuristics
    score = 100
    reasons = []
    if report.get('master_key_enc'):
        reasons.append('Master key is encrypted')
    else:
        score -= 50
        reasons.append('Master key is plain on disk')
    if report.get('recovery'):
        score -= 10
        reasons.append('Recovery token present')
    if report.get('backups'):
        score -= 10
        reasons.append('Backups present in data dir')

    md.append(f'- Overall score: **{score}/100**')
    md.append('- Reasons:')
    for r in reasons:
        md.append(f'  - {r}')
    md.append('')

    md.append('## Diagrams')
    files = [
        'app_security_current.png', 'app_security_recommended.png',
        'file_encryption_current.png', 'file_encryption_recommended.png',
        'backup_security_current.png', 'backup_security_recommended.png'
    ]
    for f in files:
        md.append(f'![]({f})')
        md.append('')

    md.append('## Comparison details (current vs recommended)')
    md.append('### Master key')
    md.append('- Current: {}'.format('encrypted' if report.get('master_key_enc') else 'plain / weakly protected'))
    md.append('- Recommended: master key encrypted using Argon2 or PBKDF2 with high cost; storage in OS keystore or hardware token')
    md.append('')
    md.append('### Backups')
    md.append('- Current: zip file encrypted with AES-GCM (may include master key)')
    md.append('- Recommended: exclude master key; add HMAC/signature; use separate password to encrypt backup')
    md.append('')
    md.append('### File encryption')
    md.append('- Current: AES-GCM; file format: IV||ciphertext||tag; original filename partially embedded in stored filename')
    md.append('- Recommended: include versioned header+meta, store MIME type, use authenticated encryption, and optionally sign metadata')

    out_md = outdir / 'security_diagrams_report.md'
    out_md.write_text('\n'.join(md), encoding='utf-8')
    return out_md


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', default=str(OUT_DIR_DEFAULT))
    p.add_argument('--data-dir', default=None)
    args = p.parse_args()
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    # generate report using analyzer if available
    if analyze is not None:
        # analyze expects a valid path; use provided data-dir or fallback to default from juman_secure
        if args.data_dir:
            report = analyze(args.data_dir)
        else:
            try:
                import juman_secure
                report = analyze(str(juman_secure.DATA_DIR))
            except Exception:
                # fallback conservative report
                report = {'master_key_enc': False, 'recovery': False, 'backups': []}
    else:
        report = {'master_key_enc': False, 'recovery': False, 'backups': []}

    app_cur, app_rec = make_app_diagrams(report, outdir)
    file_cur, file_rec = make_file_encryption_diagrams(report, outdir)
    b_cur, b_rec = make_backup_diagrams(report, outdir)

    md = generate_comparison_md(report, outdir)
    print('Diagrams and report written to', outdir)

if __name__ == '__main__':
    main()
