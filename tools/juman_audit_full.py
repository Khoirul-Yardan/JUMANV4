#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
juman_audit_full.py

Audit keamanan lanjutan untuk JuMan (Bahasa Indonesia).
- Memeriksa konfigurasi dan file sensitif
- Menjalankan serangan kamus terbatas terhadap PBKDF2 local
- Menjalankan brute-force terbatas (sangat terbatas) jika diminta
- Menghasilkan laporan HTML + PNG diagram (komponen dan risiko)

PENTING: alat ini hanya untuk audit lokal di sistem yang Anda miliki.
"""

import argparse
import base64
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
import matplotlib.pyplot as plt
import networkx as nx

from juman_secure import DATA_DIR, CONFIG_NAME, MASTER_KEY_ENC, RECOVERY, STORAGE_DIRNAME, find_stored_path

# reuse some functions for dictionary/bruteforce
import hashlib
import itertools

PBKDF2_ITER = 200_000

DEFAULT_WORDLIST = ['admin', 'password', '123456', 'qwerty', 'letmein', 'welcome', 'juman']


def read_config(data_dir: Path):
    cfg = Path(data_dir) / CONFIG_NAME
    if not cfg.exists():
        return {}
    return json.loads(cfg.read_text(encoding='utf-8'))


def load_config_hashes(data_dir: Path):
    cfg = read_config(data_dir)
    # Java version saved salt/base64 in config.properties; our secure manager stores config.json
    return cfg


def pbkdf2_check(password, salt_b64, target_b64, iterations=PBKDF2_ITER):
    salt = base64.b64decode(salt_b64)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return base64.b64encode(dk).decode('ascii') == target_b64


def run_dictionary_attack(salt_b64, target_b64, wordlist, limit=20000):
    tried = 0
    for w in wordlist:
        tried += 1
        if tried > limit:
            break
        if pbkdf2_check(w, salt_b64, target_b64):
            return w, tried
    return None, tried


def run_bruteforce(salt_b64, target_b64, charset, maxlen, max_attempts=200000):
    attempts = 0
    for l in range(1, maxlen+1):
        for tup in itertools.product(charset, repeat=l):
            attempts += 1
            if attempts > max_attempts:
                return None, attempts, 'limit'
            pwd = ''.join(tup)
            if pbkdf2_check(pwd, salt_b64, target_b64):
                return pwd, attempts, 'found'
    return None, attempts, 'exhausted'


def build_component_diagram(report, out_png: Path):
    G = nx.DiGraph()
    # nodes: User, JuManApp, storage, master.key, recovery, backups
    G.add_node('Pengguna (UI)')
    G.add_node('Aplikasi JuMan')
    G.add_node('Direktori storage')
    G.add_node('master.key.enc')
    G.add_node('recovery.txt')
    G.add_node('Backup (.jumanbackup)')

    G.add_edge('Pengguna (UI)', 'Aplikasi JuMan')
    G.add_edge('Aplikasi JuMan', 'Direktori storage')
    G.add_edge('Aplikasi JuMan', 'master.key.enc')
    G.add_edge('Aplikasi JuMan', 'recovery.txt')
    G.add_edge('Aplikasi JuMan', 'Backup (.jumanbackup)')

    plt.figure(figsize=(8,5))
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=1500, node_color='#88c0d0', arrows=True)
    plt.title('Diagram Komponen JuMan')
    out_png.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_png, bbox_inches='tight', dpi=150)
    plt.close()
    return out_png


def generate_html_report(report, diagram_png: Path, out_html: Path):
    html = []
    html.append('<!doctype html><html><head><meta charset="utf-8"><title>Audit JuMan</title></head><body>')
    html.append(f'<h1>Audit Keamanan JuMan</h1><p>Dibuat: {datetime.now(timezone.utc).isoformat()} UTC</p>')
    html.append(f'<h2>Skor: {report.get("score")}/100</h2>')
    html.append('<h3>Risiko terdeteksi</h3><ul>')
    for r in report.get('risks', []):
        html.append(f'<li>{r}</li>')
    html.append('</ul>')
    if diagram_png.exists():
        html.append('<h3>Diagram Komponen</h3>')
        html.append(f'<img src="{diagram_png.name}" style="max-width:100%">')
    html.append('<h3>Detail</h3>')
    html.append('<pre>')
    html.append(json.dumps(report, indent=2, ensure_ascii=False))
    html.append('</pre>')
    html.append('</body></html>')
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text('\n'.join(html), encoding='utf-8')
    # copy image if source and destination differ
    if diagram_png.exists():
        dest = out_html.parent / diagram_png.name
        try:
            if diagram_png.resolve() != dest.resolve():
                shutil.copy(diagram_png, dest)
        except Exception:
            # fallback: attempt copy only if destination does not exist
            try:
                if not dest.exists():
                    shutil.copy(diagram_png, dest)
            except Exception:
                pass
    return out_html


def analyze(data_dir: Path, do_dict=True, wordlist_path: Path = None, do_bruteforce=False, bf_charset='ab12', bf_maxlen=3):
    report = {}
    report['data_dir'] = str(data_dir)
    cfg = read_config(data_dir)
    report['config'] = cfg
    report['master_key_enc'] = (Path(data_dir) / MASTER_KEY_ENC).exists()
    report['recovery'] = (Path(data_dir) / RECOVERY).exists()
    report['storage_exists'] = (Path(data_dir) / STORAGE_DIRNAME).exists()
    report['backups'] = [p.name for p in Path(data_dir).glob('*.jumanbackup')]

    risks = []
    score = 100
    if report['master_key_enc']:
        risks.append('master.key disimpan (terenkripsi) di disk — baik, namun perlindungan bergantung pada kekuatan password')
    else:
        risks.append('master.key tidak terenkripsi ditemukan — sangat berisiko')
        score -= 40

    if report['recovery']:
        risks.append('recovery token ada di file — bisa dipakai untuk reset jika bocor')
        score -= 20

    # try to read config for salt/hash if exists (compat dengan Java config.properties)
    cp = Path(data_dir) / 'config.properties'
    if cp.exists():
        # parse legacy file
        props = {}
        for line in cp.read_text(encoding='utf-8').splitlines():
            if '=' in line:
                k, v = line.split('=',1)
                props[k.strip()] = v.strip()
        report['legacy_config'] = props
        if props.get('passwordChanged','false').lower() == 'true' and props.get('passwordHash') and props.get('passwordSalt'):
            if do_dict:
                wl = DEFAULT_WORDLIST
                if wordlist_path and Path(wordlist_path).exists():
                    wl = [l.strip() for l in Path(wordlist_path).read_text(encoding='utf-8').splitlines() if l.strip()]
                found, tried = run_dictionary_attack(props['passwordSalt'], props['passwordHash'], wl)
                report['dictionary'] = {'found': found, 'tried': tried}
                if found:
                    risks.append('Password akun ditemukan via serangan kamus')
                    score -= 30
            if do_bruteforce:
                pwd, attempts, status = run_bruteforce(props['passwordSalt'], props['passwordHash'], bf_charset, bf_maxlen)
                report['bruteforce'] = {'found': pwd, 'attempts': attempts, 'status': status}
                if status == 'found':
                    risks.append('Password ditemukan via brute-force')
                    score -= 40

    if report['backups']:
        risks.append('Backup ditemukan di folder data — periksa apakah backup terenkripsi dan jangan sertakan master key')
        score -= 10

    if score < 0: score = 0
    report['risks'] = risks
    report['score'] = score
    return report


def cli():
    p = argparse.ArgumentParser(description='Audit lengkap JuMan (bahasa Indonesia)')
    p.add_argument('--data-dir', default=str(DATA_DIR))
    p.add_argument('--output', default='tools/juman_audit_out')
    p.add_argument('--no-dict', action='store_true')
    p.add_argument('--bruteforce', action='store_true')
    p.add_argument('--wordlist')
    p.add_argument('--bf-charset', default='ab12')
    p.add_argument('--bf-maxlen', type=int, default=3)
    args = p.parse_args()

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    report = analyze(Path(args.data_dir), do_dict=not args.no_dict, wordlist_path=args.wordlist, do_bruteforce=args.bruteforce, bf_charset=args.bf_charset, bf_maxlen=args.bf_maxlen)
    diagram = build_component_diagram(report, outdir / 'components.png')
    out_html = generate_html_report(report, diagram, outdir / 'audit_report.html')
    print('Laporan dibuat di:', outdir)

if __name__ == '__main__':
    cli()
