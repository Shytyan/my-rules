#!/usr/bin/env python3
"""Build community rulesets (sing-box ruleset JSON) from upstream lists.

The manifest (rulesets/sources.json) describes every tag:
    {"tags": {"<tag>": {"sources": [{"url": "...", "format": "plain|v2fly|json"}],
                        "add": {"domain_suffix": [], "domain": [], "domain_regex": [], "ip_cidr": []},
                        "remove": ["value", ...]}}}

Formats:
    plain  itdoginfo/allow-domains .lst: one domain (suffix) or IPv4/IPv6 subnet per line
    v2fly  v2fly/domain-list-community data/<name>: include:, domain:, full:, regexp:, keyword:, @attr
    json   sing-box source ruleset: rules[].domain_suffix/domain/domain_regex/ip_cidr

Output: <out>/<tag>.json = {"version": 2, "rules": [{...}]} with sorted, de-duplicated fields.
A tag whose source is broken (download error, empty/garbage content, size change > --max-change)
keeps its previous file; the exit code is 1 when any tag failed.

Usage: python tools/build_rulesets.py --manifest rulesets/sources.json --out rulesets-json [--only tag] [--force]
"""
import argparse
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

RULESET_VERSION = 2
FIELDS = ("domain_suffix", "domain", "domain_regex", "ip_cidr")
MAX_CHANGE = 0.5

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")


class FetchError(Exception):
    pass


class SourceError(Exception):
    pass


class Entries(dict):
    """field -> set of values, plus counters of dropped lines."""

    def __init__(self):
        super().__init__((f, set()) for f in FIELDS)
        self.invalid = 0
        self.skipped_keywords = 0

    def update_from(self, other):
        for f in FIELDS:
            self[f] |= other[f]
        self.invalid += other.invalid
        self.skipped_keywords += other.skipped_keywords

    def count(self):
        return sum(len(v) for v in self.values())


def http_fetch(url, retries=3, timeout=60):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "podkop-build-rulesets"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8")
        except (urllib.error.URLError, OSError, UnicodeDecodeError) as e:
            last = e
            if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                break
            time.sleep(2 * (attempt + 1))
    raise FetchError(f"{url}: {last}")


def normalize_domain(value):
    d = value.strip().lower()
    if d.startswith("*."):
        d = d[2:]
    d = d.lstrip(".").rstrip(".")
    return d if DOMAIN_RE.match(d) else None


def normalize_cidr(value):
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return None


def regex_ok(value):
    try:
        re.compile(value)
        return True
    except re.error:
        return False


def _strip_comment(line):
    return line.split("#", 1)[0].strip()


def parse_plain(text):
    e = Entries()
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line:
            continue
        for prefix in ("domain:", "full:"):
            if line.lower().startswith(prefix):
                line = line[len(prefix):]
        if re.match(r"^[0-9a-fA-F:.]+(/\d+)?$", line) and (":" in line or re.match(r"^[\d.]+(/\d+)?$", line)):
            cidr = normalize_cidr(line)
            if cidr:
                e["ip_cidr"].add(cidr)
            else:
                e.invalid += 1
            continue
        d = normalize_domain(line)
        if d:
            e["domain_suffix"].add(d)
        else:
            e.invalid += 1
    return e


def _as_list(v):
    if v is None:
        return []
    return [v] if isinstance(v, str) else list(v)


def entries_from_dict(d, strict=True):
    """Ruleset-like dict (one rule or "add" block) -> Entries. strict: raise on invalid values."""
    e = Entries()

    def bad(field, value):
        if strict:
            raise SourceError(f"invalid {field} value: {value!r}")
        e.invalid += 1

    for field in ("domain_suffix", "domain"):
        for v in _as_list(d.get(field)):
            n = normalize_domain(v) if isinstance(v, str) else None
            e[field].add(n) if n else bad(field, v)
    for v in _as_list(d.get("domain_regex")):
        e["domain_regex"].add(v) if isinstance(v, str) and v and regex_ok(v) else bad("domain_regex", v)
    for v in _as_list(d.get("ip_cidr")):
        n = normalize_cidr(v) if isinstance(v, str) else None
        e["ip_cidr"].add(n) if n else bad("ip_cidr", v)
    return e


def parse_json(text):
    try:
        data = json.loads(text)
        rules = data["rules"]
        if not isinstance(rules, list):
            raise TypeError("rules is not a list")
    except (ValueError, KeyError, TypeError) as ex:
        raise SourceError(f"not a sing-box ruleset: {ex}") from ex
    e = Entries()
    for rule in rules:
        if isinstance(rule, dict):
            e.update_from(entries_from_dict(rule, strict=False))
    return e


def _v2fly_line(raw):
    line = _strip_comment(raw)
    if not line:
        return None
    tokens = line.split()
    rule, attrs = tokens[0], [t for t in tokens[1:] if t.startswith("@")]
    if rule.startswith("include:") and "@" in rule:
        rule, *inline = rule.split("@")
        attrs += ["@" + a for a in inline if a]
    return rule, attrs


def parse_v2fly(url, fetch):
    """v2fly data file with recursive include: (siblings in the same data/ directory)."""
    base, top = url.rsplit("/", 1)
    texts = {}

    def load(name):
        if name not in texts:
            texts[name] = fetch(f"{base}/{name}")
        return texts[name]

    def resolve(name, stack):
        items = []  # (kind, value, attrs)
        for raw in load(name).splitlines():
            parsed = _v2fly_line(raw)
            if not parsed:
                continue
            rule, attrs = parsed
            kind, _, value = rule.partition(":") if ":" in rule else ("domain", "", rule)
            if kind == "include":
                if value in stack:
                    continue
                want = {a[1:] for a in attrs if not a.startswith("@-")}
                drop = {a[2:] for a in attrs if a.startswith("@-")}
                for item in resolve(value, stack | {value}):
                    tags = item[2]
                    if want <= tags and not (drop & tags):
                        items.append(item)
                continue
            items.append((kind, value, {a[1:] for a in attrs}))
        return items

    e = Entries()
    for kind, value, _ in resolve(top, {top}):
        if kind == "domain":
            d = normalize_domain(value)
            e["domain_suffix"].add(d) if d else setattr(e, "invalid", e.invalid + 1)
        elif kind == "full":
            d = normalize_domain(value)
            e["domain"].add(d) if d else setattr(e, "invalid", e.invalid + 1)
        elif kind == "regexp":
            e["domain_regex"].add(value) if regex_ok(value) else setattr(e, "invalid", e.invalid + 1)
        elif kind == "keyword":
            e.skipped_keywords += 1  # Xray edition parses only suffix/full/regex
        else:
            e.invalid += 1
    return e


PARSERS = {
    "plain": lambda url, fetch: parse_plain(fetch(url)),
    "json": lambda url, fetch: parse_json(fetch(url)),
    "v2fly": parse_v2fly,
}


def validate_entries(tag, e):
    for f in ("domain_suffix", "domain"):
        for v in e[f]:
            if not DOMAIN_RE.match(v):
                raise SourceError(f"{tag}: invalid {f} {v!r}")
    for v in e["domain_regex"]:
        if not regex_ok(v):
            raise SourceError(f"{tag}: invalid domain_regex {v!r}")


def build_tag(tag, spec, fetch):
    total = Entries()
    for src in spec.get("sources", []):
        fmt, url = src.get("format"), src.get("url")
        if fmt not in PARSERS:
            raise SourceError(f"{tag}: unknown format {fmt!r} for {url}")
        e = PARSERS[fmt](url, fetch)
        if e.count() == 0:
            raise SourceError(f"{tag}: source {url} has no valid entries")
        if e.invalid or e.skipped_keywords:
            log(f"{tag}: {url}: dropped {e.invalid} invalid line(s), {e.skipped_keywords} keyword rule(s)")
        total.update_from(e)

    try:
        total.update_from(entries_from_dict(spec.get("add", {})))
    except SourceError as ex:
        raise SourceError(f"{tag}: add: {ex}") from ex
    remove = set(spec.get("remove", []))
    for f in FIELDS:
        total[f] -= remove
    if total.count() == 0:
        raise SourceError(f"{tag}: result is empty")

    rule = {f: sorted(total[f]) for f in FIELDS if total[f]}
    return {"version": RULESET_VERSION, "rules": [rule]}


def ruleset_count(rs):
    return sum(len(v) for r in rs["rules"] for v in r.values())


def check_size_change(tag, prev, new, max_change=MAX_CHANGE):
    if prev <= 0:
        return
    change = (new - prev) / prev
    if abs(change) > max_change + 1e-9:
        raise SourceError(f"{tag}: size changed {prev} -> {new} ({change:+.0%}), limit ±{max_change:.0%}; use --force")


def previous_count(path):
    try:
        with open(path, encoding="utf-8") as f:
            return parse_json(f.read()).count()
    except (OSError, SourceError):
        return 0


def log(msg):
    print(msg, file=sys.stderr)


def main(argv=None, fetch=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--manifest", default="rulesets/sources.json")
    ap.add_argument("--out", default="rulesets-json")
    ap.add_argument("--only", action="append", help="build only this tag (repeatable)")
    ap.add_argument("--force", action="store_true", help="skip the size-change guard")
    ap.add_argument("--max-change", type=float, default=MAX_CHANGE)
    args = ap.parse_args(argv)
    fetch = fetch or http_fetch

    with open(args.manifest, encoding="utf-8") as f:
        tags = json.load(f)["tags"]
    selected = args.only or list(tags)
    os.makedirs(args.out, exist_ok=True)

    failed = []
    for tag in selected:
        path = os.path.join(args.out, f"{tag}.json")
        try:
            if tag not in tags:
                raise SourceError(f"{tag}: not in manifest")
            rs = build_tag(tag, tags[tag], fetch)
            prev = previous_count(path)
            new = ruleset_count(rs)
            if not args.force:
                check_size_change(tag, prev, new, args.max_change)
        except (FetchError, SourceError) as ex:
            failed.append(tag)
            log(f"ERROR {ex}" if str(ex).startswith(tag) else f"ERROR {tag}: {ex}")
            continue
        text = json.dumps(rs, indent=2, ensure_ascii=False) + "\n"
        try:
            with open(path, encoding="utf-8", newline="") as f:
                unchanged = f.read() == text
        except OSError:
            unchanged = False
        if unchanged:
            log(f"{tag}: unchanged ({new})")
            continue
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        log(f"{tag}: written ({prev} -> {new})")

    if failed:
        log(f"FAILED: {', '.join(failed)} (previous files kept)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
