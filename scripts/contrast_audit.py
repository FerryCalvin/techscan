"""Simple contrast audit for TechScan theme tokens.
Computes WCAG contrast between foreground and background tokens.
Run: python scripts/contrast_audit.py
"""
from __future__ import annotations
import re, math, sys, json, pathlib

CSS_PATH = pathlib.Path(__file__).parent.parent / 'app' / 'static' / 'techscan.css'

# Regex to extract :root and body.light variable declarations
VAR_RE = re.compile(r'--([a-z0-9-]+):\s*([^;]+);')

# Pairs to test: (foreground_token, background_token, min_ratio)
PAIRS = [
    ('ts-text','ts-bg',4.5),
    ('ts-text-dim','ts-bg',3.0),
    ('ts-text','glass-surf-1',4.5),
    ('ts-text-dim','glass-surf-1',3.0),
    ('ts-text','glass-surf-2',4.5),
    ('ts-text','ts-panel',4.5),
    ('ts-success','glass-surf-2',3.0),
    ('ts-danger','glass-surf-2',3.0),
]

HEX_RE = re.compile(r'#([0-9a-fA-F]{3,8})')
RGBA_RE = re.compile(r'rgba?\(([^)]+)\)')

def parse_color(s: str):
    s = s.strip()
    m = HEX_RE.fullmatch(s)
    if m:
        h = m.group(1)
        if len(h) == 3:
            r,g,b = [int(c+c,16) for c in h]
            return r,g,b,1.0
        if len(h) in (6,8):
            r = int(h[0:2],16); g=int(h[2:4],16); b=int(h[4:6],16)
            a = 1.0 if len(h)==6 else int(h[6:8],16)/255.0
            return r,g,b,a
    m = RGBA_RE.fullmatch(s)
    if m:
        parts = [p.strip() for p in m.group(1).split(',')]
        r,g,b = [int(float(parts[i])) for i in range(3)]
        a = 1.0
        if len(parts) > 3:
            try: a = float(parts[3])
            except: a = 1.0
        return r,g,b,a
    # Fallback common named colors
    NAMED = {'white':'#ffffff','black':'#000000'}
    if s.lower() in NAMED:
        return parse_color(NAMED[s.lower()])
    return None

def rel_lum(rgb):
    r,g,b = [c/255.0 for c in rgb]
    def cl(x):
        return (x/12.92) if x <= 0.04045 else ((x+0.055)/1.055)**2.4
    R,G,B = cl(r),cl(g),cl(b)
    return 0.2126*R + 0.7152*G + 0.0722*B

def contrast(col1, col2):
    L1 = rel_lum(col1[:3])
    L2 = rel_lum(col2[:3])
    L1,L2 = max(L1,L2), min(L1,L2)
    return (L1+0.05)/(L2+0.05)

def extract_vars(section: str):
    return {name: val.strip() for name,val in VAR_RE.findall(section)}

def get_sections(css_text: str):
    # crude split for :root, body.light, body.high-contrast, body.light.high-contrast
    root_start = css_text.find(':root')
    light_start = css_text.find('body.light')
    hc_start = css_text.find('body.high-contrast')
    light_hc_start = css_text.find('body.light.high-contrast')
    def block(start):
        if start == -1: return ''
        brace = css_text.find('{', start)
        if brace == -1: return ''
        depth=1; i=brace+1
        while i < len(css_text) and depth>0:
            if css_text[i]=='{': depth+=1
            elif css_text[i]=='}': depth-=1
            i+=1
        return css_text[brace+1:i-1]
    return block(root_start), block(light_start), block(hc_start), block(light_hc_start)

def flatten_color(val: str):
    # If value contains gradient / multiple layers, pick first color token (# or rgba)
    m = HEX_RE.search(val) or RGBA_RE.search(val)
    if not m: return None
    if m.re is HEX_RE:
        return parse_color(m.group(0))
    return parse_color(m.group(0))

def main():
    css = CSS_PATH.read_text(encoding='utf-8')
    root_sec, light_sec, hc_sec, light_hc_sec = get_sections(css)
    root_vars = extract_vars(root_sec)
    light_vars = extract_vars(light_sec)
    hc_vars = extract_vars(hc_sec)
    light_hc_vars = extract_vars(light_hc_sec)
    reports = {}
    # Merge strategy creation
    merged_light = {**root_vars, **light_vars}
    merged_hc_dark = {**root_vars, **hc_vars}
    merged_hc_light = {**root_vars, **light_vars, **hc_vars, **light_hc_vars}
    for theme, vars_map in [
        ('dark', root_vars),
        ('light', merged_light),
        ('high-contrast-dark', merged_hc_dark),
        ('high-contrast-light', merged_hc_light),
    ]:
        theme_report = []
        for fg, bg, target in PAIRS:
            fval = vars_map.get(fg)
            bval = vars_map.get(bg)
            if not fval or not bval:
                theme_report.append({'pair':f'{fg}/{bg}','status':'missing'})
                continue
            fc = flatten_color(fval)
            bc = flatten_color(bval)
            if not fc or not bc:
                theme_report.append({'pair':f'{fg}/{bg}','status':'unparsed','f':fval,'b':bval})
                continue
            ratio = contrast(fc, bc)
            theme_report.append({'pair':f'{fg}/{bg}','ratio': round(ratio,2), 'target':target, 'pass': ratio>=target})
        reports[theme] = theme_report
    worst = []
    for theme,data in reports.items():
        for item in data:
            if 'ratio' in item:
                worst.append((item['ratio'], theme, item['pair']))
    worst.sort()
    print('Contrast Report:')
    for theme, data in reports.items():
        print(f"\n[{theme.upper()}]")
        for item in data:
            if 'ratio' not in item:
                print(f" - {item['pair']}: {item['status']}")
            else:
                status = 'PASS' if item['pass'] else 'FAIL'
                print(f" - {item['pair']}: {item['ratio']} (target {item['target']}) {status}")
    if worst:
        print('\nLowest Ratios:')
        for r, theme, pair in worst[:5]:
            print(f' {r} {theme} {pair}')
    # exit non-zero if any fail
    fails = [1 for theme,data in reports.items() for it in data if it.get('ratio') and not it['pass']]
    if fails:
        sys.exit(1)

if __name__ == '__main__':
    main()
