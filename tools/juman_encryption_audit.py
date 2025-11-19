#!/usr/bin/env python3
r"""
juman_encryption_audit.py

Comprehensive JuMan Encryption & Backup Security Audit Tool

FEATURES:
  - Scan encrypted file storage and analyze security
  - Analyze backup files for vulnerabilities
  - Security scoring (0-100 scale)
  - Attack scenario simulation (brute-force, multiple attacker profiles)
  - Multiple diagrams: security gauge, attack heatmap, KDF comparison, etc.
  - Detailed HTML reports with visual dashboard

USAGE:

1. SCAN ENCRYPTED STORAGE:
   python juman_encryption_audit.py --data-dir "C:\path\to\storage" --repo-root . --out .\audit_out

2. ANALYZE BACKUP FILE:
   python juman_encryption_audit.py --backup "C:\path\to\backup.zip.jumanbackup" --repo-root . --out .\backup_out

3. On Windows PowerShell (from repo root):
   # Storage audit
   python .\tools\juman_encryption_audit.py --data-dir "C:\Users\yarda\Documents\juman\storage" --repo-root . --out .\tools\storage_audit_out
   
   # Backup analysis
   python .\tools\juman_encryption_audit.py --backup "C:\Users\yarda\Documents\juman\juman_backup_2025-11-19T13_29_13_537709Z.zip.jumanbackup" --repo-root . --out .\tools\backup_analysis_out

DEPENDENCIES:
   pip install matplotlib jinja2 numpy

OUTPUT FILES:
   - audit_report.html / backup_analysis.html (main dashboard report)
   - audit_report.json / backup_analysis.json (detailed findings in JSON)
   - *.png files: security_gauge, attack_scenarios, kdf_comparison, 
                  file_size_hist, formats_pie, iv_lengths, vulnerability_heatmap, etc.

SECURITY SCORING:
   0-29:   CRITICAL - immediate action required
   30-49:  POOR - significant issues
   50-69:  FAIR - acceptable but improvements needed
   70-100: GOOD - strong security

ATTACK SCENARIOS HEATMAP:
   Shows estimated time to crack password with different:
   - Password entropy levels (20, 40, 60, 80 bits)
   - Attacker profiles (local, cloud GPU, botnet, enterprise)
   Color-coded: Red < 1s, Orange < 100y, Yellow < 10k y, Green > 10k y

This script is conservative: it does not attempt to decrypt anything.
It inspects headers, structure, and metadata to estimate security strength.
"""

import argparse
import json
import os
from pathlib import Path
import struct
import sys
import re
from collections import Counter, defaultdict
from datetime import datetime
import math
from datetime import datetime
import math

try:
    import matplotlib.pyplot as plt
    from jinja2 import Template
except Exception:
    print("Missing dependency: please install the required Python packages in your environment:")
    print("  pip install matplotlib jinja2")
    print("If you're using the project's virtualenv, run:")
    print("  .\\.venv\\Scripts\\pip.exe install matplotlib jinja2  # on Windows PowerShell")
    sys.exit(1)

import zipfile
import struct
import math
import tempfile

FILE_MAGIC = b'JMN1'  # file-level content magic (docs)
MASTER_MAGIC = b'JMNK'  # master.key.enc magic (docs)


def parse_jmn1_header(path: Path):
    """Parse the JMN1 header described in docs. Return dict or None."""
    with path.open('rb') as f:
        try:
            magic = f.read(4)
            if magic != FILE_MAGIC:
                return None
            version_b = f.read(1)
            if not version_b:
                return None
            version = version_b[0]
            meta_len_b = f.read(4)
            if len(meta_len_b) != 4:
                return None
            meta_len = struct.unpack('>I', meta_len_b)[0]
            meta_json = f.read(meta_len)
            iv = f.read(12)
            if len(iv) != 12:
                return None
            # We can't read ciphertext/tag easily here without decrypting; but we can
            # infer that AES-GCM with 128-bit tag is likely used (per docs).
            return {
                'format': 'JMN1',
                'version': version,
                'meta': meta_json.decode('utf-8', errors='replace'),
                'iv_len': len(iv),
            }
        except Exception:
            return None


def parse_master_enc(path: Path):
    """Parse master.key.enc header (JMNK) described in docs."""
    with path.open('rb') as f:
        try:
            magic = f.read(4)
            if magic != MASTER_MAGIC:
                return None
            version_b = f.read(1)
            if not version_b:
                return None
            version = version_b[0]
            salt_len_b = f.read(4)
            salt_len = struct.unpack('>I', salt_len_b)[0]
            salt = f.read(salt_len)
            iv_len_b = f.read(4)
            iv_len = struct.unpack('>I', iv_len_b)[0]
            iv = f.read(iv_len)
            ct_len_b = f.read(4)
            ct_len = struct.unpack('>I', ct_len_b)[0]
            # do not read ciphertext
            return {
                'format': 'JMNK',
                'version': version,
                'salt_len': salt_len,
                'iv_len': iv_len,
                'ciphertext_len': ct_len,
            }
        except Exception:
            return None


def heuristic_aes_gcm_guess(path: Path):
    """Heuristic: many AES-GCM implementations write IV (12 bytes) at start
    and append 16-byte tag at end. If file size > 32 and not textual, guess AES-GCM."""
    try:
        size = path.stat().st_size
        if size < 32:
            return None
        with path.open('rb') as f:
            start = f.read(64)
            # If file contains non-printable bytes, consider it binary
            non_printables = sum(1 for b in start if b < 9 or (b > 13 and b < 32))
            if non_printables / max(1, len(start)) > 0.1:
                # guess IV length 12, tag 16
                return {'format': 'likely-aes-gcm', 'iv_len': 12, 'tag_len': 16}
            else:
                return {'format': 'unknown-binary'}
    except Exception:
        return None


def scan_storage(root: Path):
    report = {'files': []}
    for p in root.rglob('*'):
        if p.is_file():
            entry = {'path': str(p.relative_to(root)), 'size': p.stat().st_size}
            parsed = parse_jmn1_header(p)
            if parsed:
                entry.update(parsed)
            else:
                parsed_master = parse_master_enc(p)
                if parsed_master:
                    entry.update(parsed_master)
                else:
                    heur = heuristic_aes_gcm_guess(p)
                    if heur:
                        entry.update(heur)
                    else:
                        entry['format'] = 'unknown'
            report['files'].append(entry)
    return report


def analyze_authmanager_for_kdf(repo_root: Path):
    """Try to find PBKDF2 iterations or PBEKeySpec usage in AuthManager.java."""
    candidates = []
    am_path = None
    for p in repo_root.rglob('AuthManager.java'):
        am_path = p
        break
    if not am_path:
        return {'found': False}
    text = am_path.read_text(encoding='utf-8', errors='ignore')
    # look for PBKDF2_ITER constant
    m = re.search(r'PBKDF2_ITER\s*=\s*(\d+)', text)
    if m:
        return {'found': True, 'source': str(am_path), 'iterations': int(m.group(1))}
    # look for PBEKeySpec(..., <iterations>, ...)
    m2 = re.search(r'PBEKeySpec\([^,]+,\s*[^,]+,\s*(\d+)\s*,', text)
    if m2:
        return {'found': True, 'source': str(am_path), 'iterations': int(m2.group(1))}
    return {'found': False, 'source': str(am_path)}


def generate_plots(report: dict, out_dir: Path):
    files = report['files']
    sizes = [f['size'] for f in files]
    formats = [f.get('format', 'unknown') for f in files]
    iv_lens = [f.get('iv_len') for f in files if 'iv_len' in f]

    out_dir.mkdir(parents=True, exist_ok=True)

    # File size histogram
    plt.figure(figsize=(8,4))
    if sizes:
        plt.hist(sizes, bins=30, color='#3b7dd8')
    plt.title('Distribution of Encrypted File Sizes')
    plt.xlabel('Bytes')
    plt.ylabel('Count')
    plt.tight_layout()
    sz_png = out_dir / 'file_size_hist.png'
    plt.savefig(sz_png)
    plt.close()

    # Format pie chart
    fmt_counts = Counter(formats)
    labels = list(fmt_counts.keys())
    vals = list(fmt_counts.values())
    plt.figure(figsize=(6,6))
    plt.pie(vals, labels=labels, autopct='%1.1f%%')
    plt.title('Detected Formats')
    plt.tight_layout()
    fmt_png = out_dir / 'formats_pie.png'
    plt.savefig(fmt_png)
    plt.close()

    # IV length bar (if any)
    iv_png = None
    if iv_lens:
        iv_counts = Counter(iv_lens)
        xs = list(iv_counts.keys())
        ys = [iv_counts[x] for x in xs]
        plt.figure(figsize=(6,4))
        plt.bar(xs, ys, color='#2ca02c')
        plt.title('IV Lengths Detected')
        plt.xlabel('IV length (bytes)')
        plt.ylabel('Count')
        plt.tight_layout()
        iv_png = out_dir / 'iv_lengths.png'
        plt.savefig(iv_png)
        plt.close()
    
    # Vulnerability heatmap
    vuln_png = draw_vulnerability_heatmap(files, out_dir / 'vulnerability_heatmap.png')

    return {
        'file_size_hist': str(sz_png),
        'formats_pie': str(fmt_png),
        'iv_lengths': str(iv_png) if iv_png else None,
        'vulnerability_heatmap': vuln_png
    }


HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>JuMan Encrypted Storage Audit</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin: 20px 0; }
    .card { background: #f9f9f9; padding: 15px; border-left: 4px solid #007bff; border-radius: 4px; }
    .card.critical { border-left-color: #d9534f; background: #ffe6e6; }
    .card.warning { border-left-color: #f0ad4e; background: #fff3cd; }
    .card.good { border-left-color: #5cb85c; background: #e6ffe6; }
    .card-title { font-weight: bold; font-size: 14px; margin-bottom: 5px; }
    .card-value { font-size: 20px; font-weight: bold; color: #333; }
    h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
    h2 { color: #555; margin-top: 30px; }
    .diagram { margin: 20px 0; text-align: center; }
    .diagram img { max-width: 100%; border: 1px solid #ddd; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
    td, th { border: 1px solid #ddd; padding: 10px; text-align: left; }
    th { background: #f0f0f0; font-weight: bold; }
    .score-critical { color: #d9534f; }
    .score-weak { color: #f0ad4e; }
    .score-fair { color: #ffc107; }
    .score-good { color: #5cb85c; }
  </style>
</head>
<body>
<div class="container">
  <h1>🔐 JuMan Encrypted Storage Audit Report</h1>
  
  <div class="dashboard">
    <div class="card">
      <div class="card-title">Total Files Scanned</div>
      <div class="card-value">{{ total_files }}</div>
    </div>
    <div class="card">
      <div class="card-title">Format Distribution</div>
      <div class="card-value">{{ format_count }}</div>
    </div>
    <div class="card">
      <div class="card-title">KDF Strength</div>
      <div class="card-value">{{ kdf_level }}</div>
    </div>
    <div class="card">
      <div class="card-title">Overall Risk Level</div>
      <div class="card-value {% if risk_level == 'CRITICAL' %}score-critical{% elif risk_level == 'WEAK' %}score-weak{% elif risk_level == 'FAIR' %}score-fair{% else %}score-good{% endif %}">{{ risk_level }}</div>
    </div>
  </div>
  
  <h2>Security Analysis</h2>
  <p>This storage audit scanned <b>{{ total_files }}</b> encrypted files and analyzed their format, structure, and protection mechanisms.</p>
  
  <h2>Diagrams</h2>
  
  <div class="diagram">
    <h3>File Size Distribution</h3>
    <img src="{{ file_size_hist }}" alt="File Size Histogram">
  </div>
  
  <div class="diagram">
    <h3>Detected Formats</h3>
    <img src="{{ formats_pie }}" alt="Formats Pie Chart">
  </div>
  
  {% if iv_lengths %}
  <div class="diagram">
    <h3>IV Length Distribution</h3>
    <img src="{{ iv_lengths }}" alt="IV Lengths">
  </div>
  {% endif %}
  
  <div class="diagram">
    <h3>Individual File Security Scores</h3>
    <img src="{{ vulnerability_heatmap }}" alt="Vulnerability Heatmap">
  </div>
  
  <h2>Detailed File Analysis</h2>
  <table>
    <tr>
      <th>File</th>
      <th>Size (bytes)</th>
      <th>Format</th>
      <th>IV Length</th>
      <th>Security Score</th>
      <th>Assessment</th>
    </tr>
    {% for f in files %}
    <tr>
      <td><code>{{ f.path }}</code></td>
      <td style="text-align: right;">{{ f.size }}</td>
      <td>{{ f.format }}</td>
      <td>{{ f.iv_len if f.iv_len else '-' }}</td>
      <td><b class="{% if f.file_score < 40 %}score-critical{% elif f.file_score < 60 %}score-weak{% elif f.file_score < 80 %}score-fair{% else %}score-good{% endif %}">{{ f.file_score }}/100</b></td>
      <td>{{ f.assessment }}</td>
    </tr>
    {% endfor %}
  </table>
  
  <h2>KDF Configuration</h2>
  <p>Current PBKDF2 Iterations: <b>{{ kdf_iterations_str }}</b></p>
  <p>KDF Assessment: <b>{{ kdf_description }}</b></p>
  
  <h2>Recommendations</h2>
  <ul>
    {% for rec in recommendations %}
    <li>{{ rec }}</li>
    {% endfor %}
  </ul>
  
  <hr style="margin-top: 40px;">
  <p style="color: #999; font-size: 12px;">Report generated by JuMan Security Audit Tool on {{ timestamp }}. This analysis does not attempt decryption and is for informational purposes only.</p>
</div>
</body>
</html>
"""


def write_report(report: dict, diagrams: dict, kdf_info: dict, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Compute file scores and recommendations
    files_with_scores = []
    total_score = 0
    for f in report['files']:
        file_score = compute_security_score_file(f)
        f['file_score'] = file_score['score']
        f['assessment'] = ', '.join(file_score['warnings']) if file_score['warnings'] else '✓ OK'
        files_with_scores.append(f)
        total_score += file_score['score']
    
    avg_score = total_score / len(files_with_scores) if files_with_scores else 50
    
    # Determine overall risk level
    if avg_score < 30:
        risk_level = 'CRITICAL'
    elif avg_score < 50:
        risk_level = 'WEAK'
    elif avg_score < 70:
        risk_level = 'FAIR'
    else:
        risk_level = 'GOOD'
    
    # Build recommendations based on findings
    recommendations = [
        'Regularly back up encrypted files to secure location',
        'Verify file integrity before and after transfers',
        'Keep encryption keys secure and separate from backups',
        'Monitor file access and changes',
    ]
    
    kdf_assessment = assess_kdf_strength(kdf_info.get('iterations', 65536)) if kdf_info.get('found') else {'level': 'Unknown'}
    
    if kdf_info.get('iterations', 65536) < 200000:
        recommendations.insert(0, f'CRITICAL: Increase PBKDF2 iterations from {kdf_info.get("iterations", 65536):,} to 300,000+')
    
    # Format summary
    fmt_counts = Counter([f.get('format', 'unknown') for f in files_with_scores])
    format_str = ', '.join([f'{v} {k}' for k, v in fmt_counts.items()])
    
    json_path = out_dir / 'audit_report.json'
    with json_path.open('w', encoding='utf-8') as jf:
        json.dump({
            'summary': {
                'total_files': len(files_with_scores),
                'average_score': avg_score,
                'risk_level': risk_level,
                'timestamp': datetime.now().isoformat()
            },
            'report': report,
            'kdf': kdf_info,
            'files_with_scores': files_with_scores
        }, jf, indent=2)

    tmpl = Template(HTML_TEMPLATE)
    total_files = len(files_with_scores)
    fmt_summary = Counter([f.get('format', 'unknown') for f in files_with_scores])
    html = tmpl.render(
        files=files_with_scores,
        total_files=total_files,
        format_count=len(fmt_summary),
        format_summary=dict(fmt_summary),
        file_size_hist=diagrams['file_size_hist'],
        formats_pie=diagrams['formats_pie'],
        iv_lengths=diagrams.get('iv_lengths'),
        vulnerability_heatmap=diagrams.get('vulnerability_heatmap'),
        kdf_info=(kdf_info if kdf_info.get('found') else 'Not found'),
        kdf_level=kdf_assessment.get('level', 'Unknown'),
        kdf_iterations=kdf_info.get('iterations', 65536),
        kdf_iterations_str='{:,}'.format(kdf_info.get('iterations', 65536)),
        kdf_description=kdf_assessment.get('description', 'Unknown'),
        risk_level=risk_level,
        recommendations=recommendations,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    html_path = out_dir / 'audit_report.html'
    with html_path.open('w', encoding='utf-8') as hf:
        hf.write(html)
    return {'json': str(json_path), 'html': str(html_path)}


### Backup analysis utilities (merged from analyze_backup.py)

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
    if iterations <= 0:
        iterations = 1
    guesses_per_sec = attacker_hash_per_second / iterations
    total = 2 ** password_entropy_bits
    seconds = total / guesses_per_sec
    return seconds


def assess_kdf_strength(iterations):
    """Score KDF iterations: 0-30 weak, 30-70 fair, 70-90 good, 90-100 excellent."""
    if iterations < 10000:
        return {'score': 10, 'level': 'CRITICAL', 'description': 'Iterations too low (< 10k)'}
    elif iterations < 65536:
        return {'score': 30, 'level': 'WEAK', 'description': 'Iterations low (< 65k), recommend 200k+'}
    elif iterations < 200000:
        return {'score': 60, 'level': 'FAIR', 'description': 'Fair (65k-200k), consider raising to 300k+'}
    elif iterations < 500000:
        return {'score': 80, 'level': 'GOOD', 'description': 'Good (200k-500k), meets NIST guidelines'}
    else:
        return {'score': 95, 'level': 'EXCELLENT', 'description': 'Excellent (500k+), very strong against brute-force'}


def assess_password_entropy(password_str=None):
    """Estimate password entropy if string provided; default to weak/moderate/strong guesses."""
    scores = {'weak': 20, 'moderate': 40, 'strong': 60, 'very_strong': 80}
    if password_str is None:
        return {'weak': scores['weak'], 'moderate': scores['moderate'], 'strong': scores['strong']}
    length = len(password_str)
    has_upper = any(c.isupper() for c in password_str)
    has_lower = any(c.islower() for c in password_str)
    has_digit = any(c.isdigit() for c in password_str)
    has_special = any(not c.isalnum() for c in password_str)
    charset_size = (26 * has_upper) + (26 * has_lower) + (10 * has_digit) + (32 * has_special)
    entropy = length * math.log2(charset_size) if charset_size > 0 else 0
    return {'estimated_entropy_bits': entropy, 'charset_size': charset_size, 'length': length}


def compute_security_score_file(file_info):
    """Compute security score for a single encrypted file (0-100)."""
    score = 50
    warnings = []
    
    # Format assessment
    if file_info.get('format') == 'JMN1':
        score += 15
    elif file_info.get('format') == 'JMNK':
        score += 20
    elif file_info.get('format') == 'likely-aes-gcm':
        score += 10
    else:
        score -= 10
        warnings.append('Unknown format; cannot verify encryption')
    
    # IV assessment
    if file_info.get('iv_len') == 12:
        score += 10
    elif file_info.get('iv_len'):
        score -= 5
        warnings.append(f'Unusual IV length: {file_info.get("iv_len")}')
    
    # Size check (heuristic: very small files weak against pattern analysis)
    if file_info.get('size', 0) < 100:
        score -= 10
        warnings.append(f'Small file ({file_info.get("size")} bytes) vulnerable to pattern analysis')
    
    score = max(0, min(100, score))
    return {'score': score, 'warnings': warnings}


def compute_security_score_backup(backup_info, kdf_iterations=65536):
    """Compute security score for backup file (0-100)."""
    score = 50
    warnings = []
    recommendations = []
    
    fmt = backup_info.get('detected_format', 'unknown')
    if fmt == 'zip':
        score += 10
        if backup_info.get('contains_master_key'):
            score -= 40
            warnings.append('CRITICAL: Backup contains plain master.key')
            recommendations.append('Immediately rotate master key and re-encrypt all files')
        elif backup_info.get('contains_master_key_enc'):
            score += 20
            recommendations.append('Good: master.key encrypted in backup')
        else:
            score += 15
            recommendations.append('OK: master.key not included in backup')
    elif fmt == 'signed-backup':
        score += 25
        recommendations.append('Good: backup is signed with HMAC')
    elif fmt == 'binary-encrypted':
        score += 20
        recommendations.append('Backup appears to be fully encrypted')
    else:
        score -= 20
        warnings.append('Unknown backup format')
    
    # KDF strength
    kdf_assessment = assess_kdf_strength(kdf_iterations)
    score += (kdf_assessment['score'] - 50) * 0.3  # weight KDF as 30%
    if kdf_assessment['level'] in ['WEAK', 'CRITICAL']:
        warnings.append(f"KDF: {kdf_assessment['description']}")
    recommendations.append(f"KDF Strength: {kdf_assessment['level']}")
    
    score = max(0, min(100, score))
    return {
        'score': score,
        'level': 'CRITICAL' if score < 30 else 'POOR' if score < 50 else 'FAIR' if score < 70 else 'GOOD',
        'warnings': warnings,
        'recommendations': recommendations
    }


def simulate_attacks(kdf_iterations, password_entropy_bits_range=(20, 40, 60, 80)):
    """Simulate various attack scenarios and estimate success rates."""
    scenarios = []
    attacker_rates = {
        'Local (CPU GPU)': 1e9,
        'Medium (Cloud GPU)': 1e8,
        'Strong (Botnet)': 1e10,
        'Enterprise (Quantum?)': 1e12,
    }
    for entropy_bits in password_entropy_bits_range:
        for attacker_name, rate in attacker_rates.items():
            time_seconds = analyze_password_crack_time(kdf_iterations, rate, entropy_bits)
            years = time_seconds / (365 * 24 * 3600)
            if years < 1:
                feasibility = 'CRITICAL'
                color = 'red'
            elif years < 100:
                feasibility = 'HIGH RISK'
                color = 'orange'
            elif years < 10000:
                feasibility = 'MEDIUM RISK'
                color = 'yellow'
            else:
                feasibility = 'SAFE'
                color = 'green'
            scenarios.append({
                'entropy_bits': entropy_bits,
                'attacker': attacker_name,
                'rate': rate,
                'years': years,
                'feasibility': feasibility,
                'color': color
            })
    return scenarios


def draw_security_gauge(score, out_png: Path):
    """Draw a gauge showing security score 0-100."""
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis('off')
    
    # Draw gauge background
    from matplotlib.patches import Wedge
    colors_gauge = ['red', 'orange', 'yellow', 'lightgreen', 'green']
    for i, color in enumerate(colors_gauge):
        angle_start = 180 - (i * 36)
        angle_end = 180 - ((i + 1) * 36)
        wedge = Wedge((5, 2), 3, angle_end, angle_start, color=color, alpha=0.6)
        ax.add_patch(wedge)
    
    # Draw needle
    angle = 180 - (score / 100 * 180)
    import math as m
    needle_x = 5 + 2.8 * m.cos(m.radians(angle))
    needle_y = 2 + 2.8 * m.sin(m.radians(angle))
    ax.plot([5, needle_x], [2, needle_y], 'k-', lw=3)
    ax.plot(5, 2, 'ko', ms=10)
    
    # Labels
    ax.text(1, 0.5, 'CRITICAL', ha='center', fontsize=9, color='red')
    ax.text(3, 0.5, 'WEAK', ha='center', fontsize=9, color='orange')
    ax.text(5, 0.5, 'FAIR', ha='center', fontsize=9, color='goldenrod')
    ax.text(7, 0.5, 'GOOD', ha='center', fontsize=9, color='lightgreen')
    ax.text(9, 0.5, 'SAFE', ha='center', fontsize=9, color='green')
    
    ax.text(5, 5.5, f'Security Score: {score}/100', ha='center', fontsize=14, weight='bold')
    
    plt.tight_layout()
    plt.savefig(out_png, dpi=100, bbox_inches='tight')
    plt.close()


def draw_attack_scenarios_chart(scenarios, out_png: Path):
    """Draw attack scenario heatmap."""
    import numpy as np
    
    # Extract unique entropy levels and attackers
    entropies = sorted(set(s['entropy_bits'] for s in scenarios))
    attackers = sorted(set(s['attacker'] for s in scenarios))
    
    # Create matrix: rows=entropy, cols=attacker, values=years
    data = np.zeros((len(entropies), len(attackers)))
    for i, ent in enumerate(entropies):
        for j, att in enumerate(attackers):
            matching = [s for s in scenarios if s['entropy_bits'] == ent and s['attacker'] == att]
            if matching:
                data[i, j] = matching[0]['years']
    
    # Plot heatmap
    fig, ax = plt.subplots(figsize=(10, 6))
    im = ax.imshow(np.log10(data + 1), cmap='RdYlGn', aspect='auto')
    ax.set_xticks(range(len(attackers)))
    ax.set_yticks(range(len(entropies)))
    ax.set_xticklabels(attackers, rotation=45, ha='right')
    ax.set_yticklabels([f'{e} bits' for e in entropies])
    
    # Add values to cells
    for i in range(len(entropies)):
        for j in range(len(attackers)):
            years = data[i, j]
            if years < 1:
                text = '< 1 sec'
            elif years < 365:
                text = f'{years:.1f}s'
            elif years < 365*100:
                text = f'{years/365:.1f}y'
            else:
                text = '>> 100y'
            ax.text(j, i, text, ha='center', va='center', color='black', fontsize=8)
    
    ax.set_title('Attack Scenarios: Years to Crack (log scale)', fontsize=12, weight='bold')
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Log₁₀(Years)', rotation=270, labelpad=20)
    plt.tight_layout()
    plt.savefig(out_png, dpi=100, bbox_inches='tight')
    plt.close()


def draw_kdf_comparison(current_iterations, out_png: Path):
    """Compare KDF iterations: current vs recommended standards."""
    standards = {
        'Current': current_iterations,
        'NIST Min (2024)': 210000,
        'Industry Best': 500000,
        'Maximum Safe': 1000000,
    }
    fig, ax = plt.subplots(figsize=(10, 5))
    colors = ['red' if current_iterations < v else 'green' for v in standards.values()]
    bars = ax.bar(standards.keys(), standards.values(), color=colors, alpha=0.7, edgecolor='black')
    ax.set_ylabel('PBKDF2 Iterations', fontsize=11)
    ax.set_title('KDF Strength Comparison', fontsize=12, weight='bold')
    ax.set_yscale('log')
    for bar, (name, val) in zip(bars, standards.items()):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(val):,}', ha='center', va='bottom', fontsize=10)
    plt.tight_layout()
    plt.savefig(out_png, dpi=100, bbox_inches='tight')
    plt.close()


def draw_vulnerability_heatmap(files_info, out_png: Path):
    """Draw heatmap of file vulnerabilities."""
    if not files_info:
        return None
    
    import numpy as np
    
    # Score each file
    scores = []
    labels = []
    for i, f in enumerate(files_info[:20]):  # limit to first 20 files
        file_score = compute_security_score_file(f)
        scores.append(file_score['score'])
        fname = f.get('path', f'file_{i}').split('/')[-1][:20]
        labels.append(fname)
    
    fig, ax = plt.subplots(figsize=(12, 4))
    colors_list = ['red' if s < 40 else 'orange' if s < 60 else 'yellow' if s < 80 else 'green' for s in scores]
    bars = ax.barh(labels, scores, color=colors_list, edgecolor='black')
    ax.set_xlabel('Security Score (0-100)', fontsize=11)
    ax.set_title('Individual File Security Scores', fontsize=12, weight='bold')
    ax.set_xlim(0, 100)
    for bar, score in zip(bars, scores):
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f'{int(score)}', ha='left', va='center', fontsize=9, weight='bold')
    plt.tight_layout()
    plt.savefig(out_png, dpi=100, bbox_inches='tight')
    plt.close()
    return str(out_png)


def make_bruteforce_chart(iterations, out_png: Path):
    raw_rates = [1e3, 1e5, 1e7, 1e9]
    entropies = [20, 40, 60, 80]
    data = []
    for e in entropies:
        times = [analyze_password_crack_time(iterations, r, e) for r in raw_rates]
        data.append(times)
    import numpy as np
    labels = ['1e3','1e5','1e7','1e9']
    x = np.arange(len(labels))
    width = 0.2
    plt.figure(figsize=(9,4))
    for i, e in enumerate(entropies):
        ys = [t/ (3600*24*365) for t in data[i]]
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
    plt.figure(figsize=(8,4))
    ax = plt.gca()
    ax.axis('off')
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
    draw_box(*boxes['master_key'],'Master Key\\n(if included)')
    draw_box(*boxes['kdf'],'KDF / Password')
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


BACKUP_HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>JuMan Backup Security Analysis</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .security-score { font-size: 28px; font-weight: bold; padding: 20px; border-radius: 8px; margin: 10px 0; }
    .critical { background: #ffcccc; color: #990000; }
    .poor { background: #ffe6cc; color: #994400; }
    .fair { background: #ffffcc; color: #999900; }
    .good { background: #ccffcc; color: #009900; }
    h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
    h2 { color: #555; margin-top: 30px; }
    .findings { background: #f9f9f9; padding: 15px; border-left: 4px solid #007bff; margin: 10px 0; }
    .warning { color: #d9534f; font-weight: bold; }
    .recommendation { color: #5cb85c; font-weight: bold; }
    .diagram { margin: 20px 0; text-align: center; }
    .diagram img { max-width: 100%; border: 1px solid #ddd; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; }
    td, th { border: 1px solid #ddd; padding: 10px; text-align: left; }
    th { background: #f0f0f0; font-weight: bold; }
  </style>
</head>
<body>
<div class="container">
  <h1>🔐 JuMan Backup Security Analysis Report</h1>
  
  <div class="security-score {{ security_level_lower }}">
    Security Score: {{ security_score }}/100 - {{ security_level }}
  </div>
  
  <h2>File Information</h2>
  <div class="findings">
    <p><b>Backup File:</b> {{ file }}</p>
    <p><b>Format Detected:</b> {{ findings.detected_format }}</p>
    <p><b>Analysis Date:</b> {{ timestamp }}</p>
  </div>
  
  <h2>Key Findings</h2>
  <div class="findings">
    {% for warning in warnings %}
    <p class="warning">⚠️ {{ warning }}</p>
    {% endfor %}
    
    {% for rec in recommendations %}
    <p class="recommendation">✓ {{ rec }}</p>
    {% endfor %}
  </div>
  
  {% if findings.contains_master_key %}
  <div class="findings critical">
    <h3 style="color: #990000;">🚨 CRITICAL ISSUE</h3>
    <p><b>Master Key Found in Backup (PLAIN):</b> This backup contains your master encryption key in plain text!</p>
    <p><b>Risk Level:</b> CRITICAL - If this backup is compromised, your entire system is compromised.</p>
    <p><b>Action Required:</b></p>
    <ul>
      <li>Immediately rotate your master key</li>
      <li>Re-encrypt all stored files with the new master key</li>
      <li>Delete/replace this backup</li>
      <li>Change all passwords</li>
      <li>Configure backup to exclude master.key</li>
    </ul>
  </div>
  {% elif findings.contains_master_key_enc %}
  <div class="findings good">
    <h3 style="color: #009900;">✓ GOOD PRACTICE</h3>
    <p>Master key is encrypted in backup (master.key.enc).</p>
  </div>
  {% endif %}
  
  <h2>Detailed Findings</h2>
  <table>
    <tr><th>Property</th><th>Value</th><th>Assessment</th></tr>
    {% for k, v in findings_table.items() %}
    <tr>
      <td><b>{{ k }}</b></td>
      <td>{{ v.value }}</td>
      <td>{{ v.assessment }}</td>
    </tr>
    {% endfor %}
  </table>
  
  <h2>Security Diagrams</h2>
  
  <div class="diagram">
    <h3>Security Score Gauge</h3>
    <img src="{{ gauge_png }}" alt="Security Gauge">
  </div>
  
  <div class="diagram">
    <h3>Attack Scenarios - Time to Crack (Heatmap)</h3>
    <p><i>Shows estimated years to crack password across different attackers and password strengths</i></p>
    <img src="{{ scenarios_png }}" alt="Attack Scenarios">
  </div>
  
  <div class="diagram">
    <h3>KDF Strength Comparison</h3>
    <p><i>Current iterations vs industry standards</i></p>
    <img src="{{ kdf_png }}" alt="KDF Comparison">
  </div>
  
  <div class="diagram">
    <h3>Attack Surface</h3>
    <img src="{{ attack_png }}" alt="Attack Surface">
  </div>
  
  <div class="diagram">
    <h3>Brute Force Time Estimates</h3>
    <img src="{{ brute_png }}" alt="Brute Force Estimates">
  </div>
  
  <h2>Interpretation Guide</h2>
  <div class="findings">
    <p><b>Security Score Levels:</b></p>
    <ul>
      <li><b style="color: #990000;">CRITICAL (0-29):</b> Immediate action required. System is vulnerable.</li>
      <li><b style="color: #d9534f;">POOR (30-49):</b> Significant security issues need attention.</li>
      <li><b style="color: #f0ad4e;">FAIR (50-69):</b> Acceptable but improvements recommended.</li>
      <li><b style="color: #5cb85c;">GOOD (70-100):</b> Strong security posture.</li>
    </ul>
    
    <p><b>Heatmap Color Legend (Attack Scenarios):</b></p>
    <ul>
      <li><span style="background: red; padding: 2px 5px; color: white;">Red</span> = CRITICAL (< 1 second)</li>
      <li><span style="background: orange; padding: 2px 5px;">Orange</span> = HIGH RISK (< 100 years)</li>
      <li><span style="background: yellow; padding: 2px 5px;">Yellow</span> = MEDIUM RISK (< 10,000 years)</li>
      <li><span style="background: lightgreen; padding: 2px 5px;">Green</span> = SAFE (> 10,000 years)</li>
    </ul>
  </div>
  
  <h2>Recommendations</h2>
  <div class="findings">
    <ol>
      {% for rec in all_recommendations %}
      <li>{{ rec }}</li>
      {% endfor %}
    </ol>
  </div>
  
  <hr style="margin-top: 40px;">
  <p style="color: #999; font-size: 12px;">Report generated by JuMan Security Audit Tool. This analysis is for informational purposes only and does not attempt decryption.</p>
</div>
</body>
</html>
"""


def analyze_backup(backup_path: Path, repo_root: Path, out_dir: Path):
    from datetime import datetime
    
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

    # Get KDF info
    kdf_info = analyze_authmanager_for_kdf(repo_root)
    kdf_iterations = kdf_info.get('iterations', 65536) if kdf_info.get('found') else 65536
    
    # Compute security score
    sec_score = compute_security_score_backup(findings, kdf_iterations)
    score = sec_score['score']
    level = sec_score['level']
    
    # Generate diagrams
    gauge_png = out_dir / 'security_gauge.png'
    draw_security_gauge(score, gauge_png)
    
    scenarios = simulate_attacks(kdf_iterations)
    scenarios_png = out_dir / 'attack_scenarios.png'
    draw_attack_scenarios_chart(scenarios, scenarios_png)
    
    kdf_png = out_dir / 'kdf_comparison.png'
    draw_kdf_comparison(kdf_iterations, kdf_png)
    
    attack_png = out_dir / 'attack_surface.png'
    draw_attack_surface(attack_png, findings)
    
    brute_png = out_dir / 'bruteforce_estimates.png'
    make_bruteforce_chart(kdf_iterations, brute_png)
    
    # Build findings table for HTML
    findings_table = {
        'Format': {'value': findings.get('detected_format', 'Unknown'), 'assessment': 'Backup type detected'},
        'KDF Iterations': {'value': f'{kdf_iterations:,}', 'assessment': assess_kdf_strength(kdf_iterations)['level']},
        'Master Key Plain': {'value': 'YES - CRITICAL' if findings.get('contains_master_key') else 'NO - OK', 
                            'assessment': '🚨 CRITICAL ISSUE' if findings.get('contains_master_key') else '✓ Good'},
        'Master Key Encrypted': {'value': 'YES' if findings.get('contains_master_key_enc') else 'NO', 
                                'assessment': '✓ Recommended' if findings.get('contains_master_key_enc') else 'Not present'},
    }
    
    # Build all recommendations
    all_recommendations = sec_score['recommendations'] + [
        'Increase PBKDF2 iterations to 300,000 or more',
        'Use backup encryption (signed-backup format with HMAC)',
        'Exclude master.key from backups',
        'Test restore process regularly',
        'Store backups in secure, separate location',
        'Implement versioning and retention policy',
    ]
    
    # Render HTML
    tmpl = Template(BACKUP_HTML_TEMPLATE)
    html = tmpl.render(
        file=str(backup_path),
        findings=findings,
        findings_table=findings_table,
        security_score=int(score),
        security_level=level,
        security_level_lower=level.lower().replace(' ', '_'),
        warnings=sec_score['warnings'],
        recommendations=sec_score['recommendations'],
        all_recommendations=all_recommendations,
        gauge_png=str(gauge_png),
        scenarios_png=str(scenarios_png),
        kdf_png=str(kdf_png),
        attack_png=str(attack_png),
        brute_png=str(brute_png),
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    
    html_path = out_dir / 'backup_analysis.html'
    with html_path.open('w', encoding='utf-8') as f:
        f.write(html)
    
    # Write comprehensive JSON report
    full_report = {
        'backup_file': str(backup_path),
        'timestamp': datetime.now().isoformat(),
        'security_assessment': {
            'score': score,
            'level': level,
            'warnings': sec_score['warnings'],
            'recommendations': sec_score['recommendations'],
        },
        'file_format': findings,
        'kdf_analysis': {
            'iterations': kdf_iterations,
            'assessment': assess_kdf_strength(kdf_iterations),
            'source': kdf_info.get('source', 'unknown'),
        },
        'attack_scenarios': scenarios,
    }
    
    with (out_dir / 'backup_analysis.json').open('w', encoding='utf-8') as jf:
        json.dump(full_report, jf, indent=2)
    
    return html_path


def main():
    parser = argparse.ArgumentParser(description='JuMan encryption audit and diagrams')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--data-dir', '-d', help='Path to JuMan data directory to scan')
    group.add_argument('--backup', '-b', help='Path to a single JuMan backup file to analyze')
    parser.add_argument('--repo-root', '-r', default='.', help='Path to repo root to locate AuthManager.java')
    parser.add_argument('--out', '-o', default='tools/juman_encryption_audit_out', help='Output dir for report and diagrams')
    args = parser.parse_args()

    out_dir = Path(args.out)

    if args.backup:
        bp = Path(args.backup)
        if not bp.exists():
            print('Backup not found:', bp)
            sys.exit(1)
        print('Analyzing backup:', bp)
        html = analyze_backup(bp, Path(args.repo_root), out_dir)
        print('Backup analysis written:', html)
        print('JSON report:', out_dir / 'backup_analysis.json')
        print('Diagrams:', out_dir / 'attack_surface.png', out_dir / 'bruteforce_estimates.png')
        return

    # else do storage scan
    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print('Data dir does not exist:', data_dir)
        sys.exit(1)

    print('Scanning data dir:', data_dir)
    report = scan_storage(data_dir)
    print('Found', len(report['files']), 'files')

    kdf_info = analyze_authmanager_for_kdf(Path(args.repo_root))
    print('KDF info:', kdf_info)

    diagrams = generate_plots(report, out_dir)
    out_files = write_report(report, diagrams, kdf_info, out_dir)

    print('Report written to:', out_files['html'])
    print('Raw JSON report:', out_files['json'])
    print('Diagrams:', diagrams)


if __name__ == '__main__':
    main()
