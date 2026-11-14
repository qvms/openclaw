#!/usr/bin/env python3
import argparse, ipaddress, re, sys, os
from urllib.parse import urlsplit

IP_RE = re.compile(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])')

def norm_host(h):
    return h.strip().strip('.').lower()

def split_target(tok):
    """Return (host, path) for a host / host:port / URL / host/path token."""
    t = tok.strip()
    if '://' not in t:
        t = 'x://' + t
    u = urlsplit(t)
    host = norm_host(u.hostname or '')
    return host, (u.path or '')

def load_oos(path):
    exact, wild, nets, paths = set(), set(), [], []
    with open(path) as f:
        for raw in f:
            s = raw.split('#', 1)[0].strip()
            if not s:
                continue
            try:
                nets.append(ipaddress.ip_network(s, strict=False)); continue
            except ValueError:
                pass
            if s.startswith('*.'):
                wild.add(norm_host(s[2:])); continue
            host, p = split_target(s)
            if not host:
                continue
            if p and p != '/':
                paths.append((host, p.rstrip('/')))
            else:
                exact.add(host)
    return exact, wild, nets, paths

def ip_in(ipstr, nets):
    try:
        ip = ipaddress.ip_address(ipstr)
    except ValueError:
        return None
    for n in nets:
        if ip.version == n.version and ip in n:
            return n
    return None

def verdict(line, exact, wild, nets, paths):
    tok = line.split()[0]
    host, p = split_target(tok)
    if not host:
        return None
    if host in exact:
        return 'exact:' + host
    for w in wild:
        if host == w or host.endswith('.' + w):
            return 'wildcard:*.' + w
    hit = ip_in(host, nets)
    if hit:
        return 'cidr:' + str(hit)
    for ipm in IP_RE.findall(line):
        hit = ip_in(ipm, nets)
        if hit:
            return 'cidr:%s(%s)' % (hit, ipm)
    if p and p != '/':
        pp = p.rstrip('/')
        for ph, pfx in paths:
            if host == ph and (pp == pfx or pp.startswith(pfx + '/')):
                return 'path:%s%s' % (ph, pfx)
    return None

def main():
    a = argparse.ArgumentParser()
    a.add_argument('--oos', required=True)
    a.add_argument('--in', dest='inp', required=True)
    a.add_argument('--out')
    a.add_argument('--dropped')
    a.add_argument('--allow-empty-oos', action='store_true')
    o = a.parse_args()
    if not os.path.isfile(o.oos):
        if o.allow_empty_oos:
            exact = wild = set(); nets = []; paths = []
        else:
            print('FAIL-LOUD: oos file missing: %s' % o.oos, file=sys.stderr); return 2
    else:
        exact, wild, nets, paths = load_oos(o.oos)
    if not os.path.isfile(o.inp):
        print('FAIL-LOUD: input missing: %s' % o.inp, file=sys.stderr); return 3
    keep, drop = [], []
    with open(o.inp) as f:
        for line in f:
            s = line.rstrip('\n')
            if not s.strip():
                continue
            r = verdict(s, exact, wild, nets, paths)
            (drop if r else keep).append((s, r))
    out = o.out or o.inp
    tmp = out + '.oos-tmp'
    with open(tmp, 'w') as f:
        for s, _ in keep:
            f.write(s + '\n')
    os.replace(tmp, out)
    if o.dropped:
        with open(o.dropped, 'a') as f:
            for s, r in drop:
                f.write('%s\t%s\t%s\n' % (os.path.basename(o.inp), r, s))
    print('oos-gate in=%s kept=%d dropped=%d oos[exact=%d wild=%d cidr=%d path=%d]' % (
        o.inp, len(keep), len(drop), len(exact), len(wild), len(nets), len(paths)))
    return 0

if __name__ == '__main__':
    sys.exit(main())
