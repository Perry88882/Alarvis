# -*- coding: utf-8 -*-
"""W05 independent recomputation from raw JSONL.

Reads only archived raw responses and terminal-state metadata. Emits JSON + Markdown.
No API calls, no writes to the manuscript.
"""
import csv
import json
import math
import os
import sys
from collections import defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RES = os.path.join(ROOT, 'data', 'responses')
ALPHA = os.path.join(RES, 'alpha')
BETA = os.path.join(RES, 'beta')
META = os.path.join(ROOT, 'data', 'manifests')
OUT = os.path.join(ROOT, 'recompute_out')
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, os.path.dirname(__file__))
from realpe_score import parse_verdict  # noqa: E402


def wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return None
    k = min(b, c)
    return min(1.0, 2.0 * sum(math.comb(n, i) for i in range(k + 1)) / (2.0 ** n))


def holm(pvals):
    """pvals: list of (name, p). Returns dict name -> adjusted p."""
    items = [(n, p) for n, p in pvals if p is not None]
    items.sort(key=lambda x: x[1])
    m = len(items)
    out = {}
    prev = 0.0
    for i, (n, p) in enumerate(items):
        adj = min(1.0, (m - i) * p)
        adj = max(adj, prev)
        out[n] = adj
        prev = adj
    for n, p in pvals:
        if p is None:
            out[n] = None
    return out


def majority(vals):
    a = [v for v in vals if v in ('malicious', 'benign')]
    if not a:
        return None
    if a.count('malicious') * 2 > len(a):
        return 'malicious'
    if a.count('benign') * 2 > len(a):
        return 'benign'
    return None


def load_jsonl(p):
    rows = []
    with open(p, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# ---------- alpha ----------
def alpha():
    out = {}
    by_model = defaultdict(list)
    for r in load_jsonl(os.path.join(RES, 'alpha.jsonl')):
        by_model[r['model']].append(r)
    for model, rows in sorted(by_model.items()):
        acc = defaultdict(list)
        status = defaultdict(int)
        for r in rows:
            pv = parse_verdict(r.get('content') or '')
            status[pv['status']] += 1
            acc[(r['cond'], r['program'])].append(pv['verdict'])
        cells = {}
        for c in (1, 2, 3):
            for truth, pref in (('benign', 'hb'), ('malicious', 'hm')):
                vals = [majority(v) for (cc, n), v in acc.items() if cc == c and n.startswith(pref)]
                valid = [v for v in vals if v]
                k = sum(1 for v in valid if v == 'malicious')
                cells[f'{c}|{truth}'] = {'k': k, 'n': len(valid), 'void': len(vals) - len(valid),
                                        'rate': k / len(valid) if valid else None,
                                        'wilson95': wilson(k, len(valid))}
        pairs = {}
        for a, b in ((1, 2), (2, 3), (1, 3)):
            for truth, pref in (('benign', 'hb'), ('malicious', 'hm')):
                bb = cc = both = neither = 0
                for (cond, name), v in acc.items():
                    if cond != a or not name.startswith(pref):
                        continue
                    va = majority(v)
                    vb = majority(acc.get((b, name), []))
                    if va is None or vb is None:
                        continue
                    ok_a = (va == 'malicious') == (truth == 'malicious')
                    ok_b = (vb == 'malicious') == (truth == 'malicious')
                    if ok_a and not ok_b:
                        bb += 1
                    elif ok_b and not ok_a:
                        cc += 1
                    elif ok_a and ok_b:
                        both += 1
                    else:
                        neither += 1
                pairs[f'{a}->{b}|{truth}'] = {'before_correct': bb, 'after_correct': cc,
                                               'both_correct': both, 'both_wrong': neither,
                                               'p_exact': mcnemar_exact(bb, cc)}
        out[model] = {'file': 'alpha.jsonl', 'rows': len(rows),
                      'status': dict(status), 'cells': cells, 'paired': pairs}
    # deltas
    deltas = {}
    for name, d in out.items():
        c = d['cells']
        vals = {}
        for a, b in ((1, 2), (2, 3), (1, 3)):
            fa, fb = c[f'{a}|benign']['rate'], c[f'{b}|benign']['rate']
            vals[f'{a}->{b}'] = None if fa is None or fb is None else 100 * (fb - fa)
        deltas[name] = vals
    def summ(key):
        xs = [v[key] for v in deltas.values() if v[key] is not None]
        m = sum(xs) / len(xs)
        sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))
        return {'mean': m, 'sd': sd, 'min': min(xs), 'max': max(xs), 'n': len(xs),
                'per_model': {k: v[key] for k, v in deltas.items()}}
    return {'models': out, 'delta_fpr': {k: summ(k) for k in ('1->2', '2->3', '1->3')}}


# ---------- beta ----------
def beta():
    out = {}
    by_model = defaultdict(list)
    for r in load_jsonl(os.path.join(RES, 'beta.jsonl')):
        by_model[r['model']].append(r)
    for model, rows_in in sorted(by_model.items()):
        acc = defaultdict(list)
        for r in rows_in:
            pv = parse_verdict(r.get('content') or '')
            acc[(r['cond'], r['program'])].append(pv['verdict'])
        rows = {}
        for c in range(1, 7):
            row = {}
            for truth, pref in (('benign', 'b'), ('malicious', 'm')):
                vals = [majority(v) for (cc, n), v in acc.items() if cc == c and n.startswith(pref)]
                valid = [v for v in vals if v]
                k = sum(1 for v in valid if v == 'malicious')
                row[truth] = {'k': k, 'n': len(valid), 'void': len(vals) - len(valid),
                              'rate': k / len(valid) if valid else None,
                              'wilson95': wilson(k, len(valid))}
            rows[c] = row
        out[model] = {'file': 'beta.jsonl', 'rows': len(rows_in), 'conditions': rows}
    return out


# ---------- M03 ----------
def m03():
    rows = load_jsonl(os.path.join(RES, 'm03_raw.jsonl'))
    acc = defaultdict(list)
    for r in rows:
        acc[(r['model'], r['program'], r['condition'])].append(r.get('verdict'))
    conv = {}
    for k, vals in acc.items():
        valid = [v for v in vals if v in ('malicious', 'benign')]
        conv[k] = {'valid': len(valid), 'malicious': valid.count('malicious'),
                   'convicted': len(valid) >= 3 and valid.count('malicious') >= 3}
    models = sorted({k[0] for k in acc})
    progs = sorted({k[1] for k in conv})
    desc = {}
    for m in models:
        desc[m] = {}
        for arm in 'HABC':
            ks = [conv[(m, p, arm)]['convicted'] for p in progs]
            desc[m][arm] = {'convicted': sum(ks), 'n': len(ks),
                            'rate': sum(ks) / len(ks),
                            'wilson95': wilson(sum(ks), len(ks))}
    main = {}
    for m in models:
        bb = cc = both = neither = 0
        for p in progs:
            b = conv[(m, p, 'B')]['convicted']
            c = conv[(m, p, 'C')]['convicted']
            if b and not c:
                bb += 1
            elif c and not b:
                cc += 1
            elif b and c:
                both += 1
            else:
                neither += 1
        main[m] = {'b_only': bb, 'c_only': cc, 'both': both, 'neither': neither,
                   'p_exact': mcnemar_exact(bb, cc)}
    raw_p = {'B_vs_C|' + m: main[m]['p_exact'] for m in models}
    adj = holm(list(raw_p.items()))
    for m in models:
        main[m]['p_holm'] = adj['B_vs_C|' + m]
    return {'rows': len(rows), 'models': models, 'programs': len(progs),
            'conviction_rule': '>=3 valid and >=3 malicious',
            'descriptive': desc, 'main_B_vs_C': main}


# ---------- M04 ----------
def m04():
    rows = load_jsonl(os.path.join(RES, 'm04_raw.jsonl'))
    term = {}
    with open(os.path.join(META, 'm04_terminal_states.csv'), encoding='utf-8-sig') as f:
        for r in csv.DictReader(f):
            term[(r['project'], r['version'])] = r
    acc = defaultdict(list)
    for r in rows:
        acc[(r['model'], r['program'], r['condition'])].append(r.get('verdict'))
    models = sorted({k[0] for k in acc})
    projects = sorted({k[1] for k in acc})
    prog = {}
    for k, vals in acc.items():
        verdicts = [v for v in vals if v in ('malicious', 'benign')]
        st = term.get((k[1], k[2]), {})
        empty_input = st.get('select_state') == 'empty_input' or st.get('n_functions_total') in ('0', '0.0')
        state = 'ok' if len(verdicts) >= 2 else 'undetermined'
        prog[k] = {'valid': len(verdicts), 'malicious': verdicts.count('malicious'),
                   'verdict': majority(verdicts) if state == 'ok' else None,
                   'empty_input': bool(empty_input),
                   'in_denominator': st.get('counts_in_confirm_denominator') == '1',
                   'state': state}
    cells = {}
    for m in models:
        for v in ('P0', 'P1', 'P2'):
            vals = [prog[(m, p, v)] for p in projects if (m, p, v) in prog]
            raw_den = [x for x in vals if x['state'] == 'ok']
            nonempty = [x for x in vals if x['state'] == 'ok' and not x['empty_input']]
            cells[f'{m}|{v}|raw'] = {'malicious': sum(1 for x in raw_den if x['verdict'] == 'malicious'),
                                     'n': len(raw_den)}
            cells[f'{m}|{v}|nonempty'] = {'malicious': sum(1 for x in nonempty if x['verdict'] == 'malicious'),
                                          'n': len(nonempty)}
    paired = {}
    for m in models:
        bb = cc = both = neither = 0
        used = []
        for p in projects:
            a = prog.get((m, p, 'P0'))
            b = prog.get((m, p, 'P1'))
            if not a or not b or a['state'] != 'ok' or b['state'] != 'ok':
                continue
            used.append(p)
            ma, mb = a['verdict'] == 'malicious', b['verdict'] == 'malicious'
            if ma and not mb:
                bb += 1
            elif mb and not ma:
                cc += 1
            elif ma and mb:
                both += 1
            else:
                neither += 1
        paired[m] = {'P0_only_malicious': bb, 'P1_only_malicious': cc,
                     'both_malicious': both, 'neither_malicious': neither,
                     'p_exact': mcnemar_exact(bb, cc), 'n_pairs': len(used)}
    timeouts = [(k, v) for k, v in term.items() if v.get('dump_state', '').startswith('timeout')]
    zero = [(k, v) for k, v in term.items() if v.get('dump_state') == 'zero_functions']
    # 324 confirm requests = 54 versions × 2 models × 3 reps; zero-function P1s were queued
    # but excluded from the analysis denominator (counts_in_confirm_denominator=0).
    queued = [k for k, v in term.items() if v.get('dump_state') != 'timeout_1800s']
    in_den = [k for k, v in term.items() if str(v.get('counts_in_confirm_denominator')) == '1']
    return {'rows': len(rows), 'models': models, 'projects': len(projects),
            'terminal': {'versions': len(term), 'queued': len(queued),
                         'in_analysis_denominator': len(in_den),
                         'timeouts': [list(k) for k, _ in timeouts],
                         'zero_function': [list(k) for k, _ in zero]},
            'cells': cells, 'paired_P0_P1': paired, 'program_level': {
                '|'.join(k): v for k, v in prog.items()}}


# ---------- M04b ----------
def m04b():
    p = os.path.join(RES, 'bridge_raw.jsonl')
    rows = load_jsonl(p)
    acc = defaultdict(list)
    for r in rows:
        acc[(r['program'], r['condition'], r['model'])].append(r.get('verdict'))
    cells = {}
    for k, vals in acc.items():
        valid = [v for v in vals if v in ('malicious', 'benign')]
        cells['|'.join(k)] = {'malicious': valid.count('malicious'), 'valid': len(valid),
                              'raw_rows': len(vals), 'verdicts': vals}
    # aggregate by version
    by_ver = {}
    for ver in ('clean', 'protected'):
        vals = [v for (proj, vv, m), vs in acc.items() if vv == ver for v in vs
                if v in ('malicious', 'benign')]
        by_ver[ver] = {'malicious': vals.count('malicious'), 'valid': len(vals)}
    return {'rows': len(rows), 'cells': cells, 'by_version': by_ver}


def main():
    data = {'alpha': alpha(), 'beta': beta(), 'M03': m03(), 'M04': m04(), 'M04b': m04b()}
    with open(os.path.join(OUT, 'historical_recompute.json'), 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    L = []
    L.append('# Independent recomputation from raw JSONL')
    L.append('')
    L.append('> No new model calls; reads only the archived responses and terminal-state tables.')
    L.append('> Strict parsing reuses `realpe_score.parse_verdict`; M03/M04/M04b use the archived `verdict` field.')
    L.append('')
    L.append('## 1. alpha: nine models, three stages')
    L.append('')
    L.append('| Model | H1 alarms | H3 alarms | H4 alarms | H1->H3 | H3->H4 | H1->H4 |')
    L.append('|---|---:|---:|---:|---:|---:|---:|')
    for m, d in data['alpha']['models'].items():
        c = d['cells']
        def f(x):
            return f"{x['k']}/{x['n']} ({100*x['rate']:.1f}%)" if x['rate'] is not None else '—'
        v = data['alpha']['delta_fpr']
        def g(key):
            x = v[key]['per_model'].get(m)
            return '—' if x is None else f'{x:+.1f}'
        L.append(f"| {m} | {f(c['1|benign'])} | {f(c['2|benign'])} | {f(c['3|benign'])} | {g('1->2')} | {g('2->3')} | {g('1->3')} |")
    L.append('')
    for key, label in (('1->2', 'H1->H3'), ('2->3', 'H3->H4'), ('1->3', 'H1->H4')):
        d = data['alpha']['delta_fpr'][key]
        L.append(f"- {label} delta false alarms: mean {d['mean']:+.1f}, sd {d['sd']:.1f}, "
                 f"range [{d['min']:+.1f}, {d['max']:+.1f}], n={d['n']}.")
    L.append('')
    L.append('Paper values: +29.8 / +36.6 / +66.4 (sd 12.4, range 50-90).')
    L.append('')
    L.append('### Paired test (benign side; $b$ = malicious only in the later stage, $c$ = only in the earlier stage)')
    L.append('')
    L.append('| Model | H1->H3 b/c | p | H3->H4 b/c | p | H1->H4 b/c | p |')
    L.append('|---|---:|---:|---:|---:|---:|---:|')
    for m, d in data['alpha']['models'].items():
        cells = []
        for key in ('1->2', '2->3', '1->3'):
            x = d['paired'][key + '|benign']
            cells.append(f"{x['before_correct']}/{x['after_correct']}")
            cells.append('—' if x['p_exact'] is None else
                         ('<0.0001' if x['p_exact'] < 0.0001 else f"{x['p_exact']:.4f}"))
        L.append(f"| {m} | " + ' | '.join(cells) + ' |')
    L.append('')
    L.append('Paper Table `tab:mcnemar`: all nine models have $c=0$ on H1->H4, with p from $<0.0001$ to $0.0020$; the Claude exception on H1->H3 is b=4/c=1/p=0.375.')
    L.append('')
    L.append('## 2. beta: benign alarms by model and level')
    L.append('')
    L.append('| Model | L0 | L1 | L2 | L3 | L4 | L5 |')
    L.append('|---|---:|---:|---:|---:|---:|---:|')
    for m, d in data['beta'].items():
        cells = []
        for c in range(1, 7):
            x = d['conditions'][c]['benign']
            cells.append(f"{x['k']}/{x['n']}")
        L.append('| ' + m + ' | ' + ' | '.join(cells) + ' |')
    L.append('')
    L.append('Paper: seven models alarm on 20/20 at L2; Gemini is 10/18, with two more cells lacking a valid verdict.')
    L.append('')
    L.append('## 3. M03: B vs C')
    L.append('')
    L.append('| Model | H | A | B | C | B only malicious | C only malicious | Exact p | Holm p |')
    L.append('|---|---:|---:|---:|---:|---:|---:|---:|---:|')
    for m, d in data['M03']['descriptive'].items():
        mb = data['M03']['main_B_vs_C'][m]
        L.append(f"| {m} | {d['H']['convicted']}/20 | {d['A']['convicted']}/20 | {d['B']['convicted']}/20 | {d['C']['convicted']}/20 | {mb['b_only']} | {mb['c_only']} | {mb['p_exact']:.4f} | {mb['p_holm']:.4f} |")
    L.append('')
    L.append('Paper: DeepSeek B/C 9/0, p=0.0039, Holm=0.0078; Gemini 3/0, p=0.25.')
    L.append('')
    L.append('## 4. M04: P0/P1/P2')
    L.append('')
    L.append('| Denominator | DeepSeek | Gemini |')
    L.append('|---|---:|---:|')
    for tag in ('P0|raw', 'P1|raw', 'P2|raw', 'P0|nonempty', 'P1|nonempty', 'P2|nonempty'):
        vals = []
        for m in data['M04']['models']:
            x = data['M04']['cells'][f'{m}|{tag}']
            vals.append(f"{x['malicious']}/{x['n']}")
        L.append(f"| {tag} | {vals[0]} | {vals[1] if len(vals)>1 else '—'} |")
    L.append('')
    for m, d in data['M04']['paired_P0_P1'].items():
        L.append(f"- {m}: P0 only malicious {d['P0_only_malicious']}, P1 only malicious "
                 f"{d['P1_only_malicious']}, both malicious {d['both_malicious']}, neither "
                 f"{d['neither_malicious']}, n={d['n_pairs']}, exact p={d['p_exact']:.4f}.")
    t = data['M04']['terminal']
    L.append(f"- Terminal states: {t['versions']} versions, {t['queued']} queued, "
             f"{t['in_analysis_denominator']} enter the analysis denominator; "
             f"{len(t['timeouts'])} timed out; {len(t['zero_function'])} P1 versions had zero functions.")
    L.append('')
    L.append('Paper: DeepSeek P1 17/20 (17/17 non-empty); Gemini P1 17/17 (17/17 non-empty); DeepSeek P0/P1 p~0.0001, Gemini p~0.0002.')
    L.append('')
    L.append('### Wilson 95% intervals for key rates')
    L.append('')
    L.append('| Rate | k/n | Wilson 95% |')
    L.append('|---|---:|---|')
    wl = [
        ('alpha DeepSeek H4 benign alarm', data['alpha']['models']['deepseek']['cells']['3|benign']),
        ('alpha DeepSeek H1 benign alarm', data['alpha']['models']['deepseek']['cells']['1|benign']),
        ('M03 DeepSeek B convictions', data['M03']['descriptive']['deepseek']['B']),
        ('M03 Gemini B convictions', data['M03']['descriptive']['gemini']['B']),
        ('M04 DeepSeek P1 malicious (raw denominator)', data['M04']['cells']['deepseek|P1|raw']),
        ('M04 Gemini P1 malicious (raw denominator)', data['M04']['cells']['gemini|P1|raw']),
        ('M04b protected malicious', data['M04b']['by_version']['protected']),
    ]
    for name, x in wl:
        k = x.get('k', x.get('malicious', x.get('convicted')))
        n = x.get('n', x.get('valid'))
        lo, hi = wilson(k, n)
        L.append(f"| {name} | {k}/{n} | [{100*lo:.1f}, {100*hi:.1f}] |")
    L.append('')
    L.append('## 5. M04b')
    L.append('')
    L.append('| Version | Malicious / valid |')
    L.append('|---|---:|')
    for ver, d in data['M04b']['by_version'].items():
        L.append(f"| {ver} | {d['malicious']}/{d['valid']} |")
    L.append('')
    L.append('M04b is not reported in the paper; the pilot recorded clean 0/8 and protected 3/8.')
    L.append('')
    L.append('## 6. Automatic consistency checks')
    L.append('')
    checks = []
    a = data['alpha']['delta_fpr']
    checks.append(('alpha H1->H3 mean ~ 29.8', abs(a['1->2']['mean'] - 29.8) < 0.2, f"{a['1->2']['mean']:.2f}"))
    checks.append(('alpha H3->H4 mean ~ 36.6', abs(a['2->3']['mean'] - 36.6) < 0.2, f"{a['2->3']['mean']:.2f}"))
    checks.append(('alpha H1->H4 mean ~ 66.4', abs(a['1->3']['mean'] - 66.4) < 0.2, f"{a['1->3']['mean']:.2f}"))
    checks.append(('alpha delta sd ~ 12.4', abs(a['1->3']['sd'] - 12.4) < 0.2, f"{a['1->3']['sd']:.2f}"))
    ds_a = data['alpha']['models']['deepseek']['paired']['1->3|benign']
    cl_a = data['alpha']['models']['claude-sonnet-5-5']['paired']['1->2|benign']
    all_c0 = all(d['paired']['1->3|benign']['after_correct'] == 0
                 for d in data['alpha']['models'].values())
    checks.append(('alpha H1->H4: all c=0', all_c0, 'yes' if all_c0 else 'no'))
    checks.append(('alpha DeepSeek H1->H4 b=12, p=0.0005',
                   ds_a['before_correct'] == 12 and abs(ds_a['p_exact'] - 0.000488) < 0.0001,
                   f"b={ds_a['before_correct']}, p={ds_a['p_exact']:.6f}"))
    checks.append(('alpha Claude H1->H3 b=4/c=1/p=0.375',
                   cl_a['before_correct'] == 4 and cl_a['after_correct'] == 1
                   and abs(cl_a['p_exact'] - 0.375) < 0.001,
                   f"b={cl_a['before_correct']}/c={cl_a['after_correct']}, p={cl_a['p_exact']:.4f}"))
    ds = data['M03']['main_B_vs_C'].get('deepseek', {})
    gm = data['M03']['main_B_vs_C'].get('gemini', {})
    checks.append(('M03 DS b/c = 9/0', ds.get('b_only') == 9 and ds.get('c_only') == 0,
                   f"{ds.get('b_only')}/{ds.get('c_only')}"))
    checks.append(('M03 Gemini b/c = 3/0', gm.get('b_only') == 3 and gm.get('c_only') == 0,
                   f"{gm.get('b_only')}/{gm.get('c_only')}"))
    m4 = data['M04']['cells']
    checks.append(('M04 DS P1 raw 17/20', m4['deepseek|P1|raw']['malicious'] == 17 and m4['deepseek|P1|raw']['n'] == 20,
                   f"{m4['deepseek|P1|raw']['malicious']}/{m4['deepseek|P1|raw']['n']}"))
    checks.append(('M04 DS P1 nonempty 17/17', m4['deepseek|P1|nonempty']['malicious'] == 17 and m4['deepseek|P1|nonempty']['n'] == 17,
                   f"{m4['deepseek|P1|nonempty']['malicious']}/{m4['deepseek|P1|nonempty']['n']}"))
    checks.append(('M04 Gemini P1 nonempty 17/17', m4['gemini|P1|nonempty']['malicious'] == 17 and m4['gemini|P1|nonempty']['n'] == 17,
                   f"{m4['gemini|P1|nonempty']['malicious']}/{m4['gemini|P1|nonempty']['n']}"))
    b = data['M04b']['by_version']
    checks.append(('M04b clean 0/8', b['clean']['malicious'] == 0 and b['clean']['valid'] == 8,
                   f"{b['clean']['malicious']}/{b['clean']['valid']}"))
    checks.append(('M04b protected 3/8', b['protected']['malicious'] == 3 and b['protected']['valid'] == 8,
                   f"{b['protected']['malicious']}/{b['protected']['valid']}"))
    L.append('| Check | Result | Recomputed |')
    L.append('|---|---|---|')
    for name, ok, val in checks:
        L.append(f"| {name} | {'PASS' if ok else 'CHECK'} | {val} |")
    L.append('')
    with open(os.path.join(OUT, 'historical_recompute.md'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
