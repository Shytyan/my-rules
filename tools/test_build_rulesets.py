"""Unit tests for tools/build_rulesets.py (no network: sources are served by a fake fetcher).

Run: python -m unittest tools/test_build_rulesets.py -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_rulesets as br  # noqa: E402

V2 = "https://example.test/v2fly/data"


def fake_fetch(files):
    def fetch(url):
        if url not in files:
            raise br.FetchError(f"404 {url}")
        return files[url]
    return fetch


class ParsePlain(unittest.TestCase):
    def test_domains_and_subnets(self):
        e = br.parse_plain("Example.ORG\n# c\n*.foo.net\r\n.bar.com\n\nbad domain!\n203.0.113.0/24\n198.51.100.7\n")
        self.assertEqual(e["domain_suffix"], {"example.org", "foo.net", "bar.com"})
        self.assertEqual(e["ip_cidr"], {"203.0.113.0/24", "198.51.100.7/32"})
        self.assertEqual(e.invalid, 1)

    def test_ipv6_subnets(self):
        # core.telegram.org/resources/cidr.txt mixes IPv4 and IPv6
        e = br.parse_plain("91.108.56.0/22\n2001:b28:f23d::/48\n2a0a:f280::/32\n2001:DB8::1\n")
        self.assertEqual(e["ip_cidr"], {"91.108.56.0/22", "2001:b28:f23d::/48", "2a0a:f280::/32", "2001:db8::1/128"})
        self.assertEqual(e["domain_suffix"], set())
        self.assertEqual(e.invalid, 0)

    def test_single_label_suffix_allowed(self):
        self.assertEqual(br.parse_plain("ua\n")["domain_suffix"], {"ua"})


class ParseJson(unittest.TestCase):
    def test_singbox_ruleset(self):
        text = json.dumps({"version": 2, "rules": [
            {"domain_suffix": ["a.org"], "domain": "exact.a.org", "domain_regex": ["^x\\.a\\.org$"], "ip_cidr": ["192.0.2.0/24"]}]})
        e = br.parse_json(text)
        self.assertEqual(e["domain_suffix"], {"a.org"})
        self.assertEqual(e["domain"], {"exact.a.org"})
        self.assertEqual(e["domain_regex"], {"^x\\.a\\.org$"})
        self.assertEqual(e["ip_cidr"], {"192.0.2.0/24"})

    def test_broken_json_raises(self):
        with self.assertRaises(br.SourceError):
            br.parse_json("{not json")


class V2fly(unittest.TestCase):
    def files(self):
        return {
            f"{V2}/svc": "# top\ninclude:svc-cdn\ninclude:svc-ads @ads\nsvc.com\ndomain:svc.net\nfull:api.svc.com\n"
                         "regexp:^x\\d+\\.svc\\.com$\nkeyword:svc\nsvc.cn @cn\n",
            f"{V2}/svc-cdn": "cdn-svc.com\ninclude:svc  # cycle\n",
            f"{V2}/svc-ads": "ads.svc.com @ads\ntracker.svc.com\n",
        }

    def test_include_recursive_with_types(self):
        e = br.parse_v2fly(f"{V2}/svc", fake_fetch(self.files()))
        self.assertEqual(e["domain_suffix"], {"svc.com", "svc.net", "cdn-svc.com", "ads.svc.com", "svc.cn"})
        self.assertEqual(e["domain"], {"api.svc.com"})
        self.assertEqual(e["domain_regex"], {"^x\\d+\\.svc\\.com$"})
        self.assertEqual(e.skipped_keywords, 1)

    def test_attribute_filters(self):
        files = self.files()
        files[f"{V2}/top"] = "include:svc @-cn\n"
        e = br.parse_v2fly(f"{V2}/top", fake_fetch(files))
        self.assertNotIn("svc.cn", e["domain_suffix"])
        self.assertIn("svc.com", e["domain_suffix"])
        # include:svc-ads @ads inside svc keeps only @ads entries
        self.assertNotIn("tracker.svc.com", e["domain_suffix"])

    def test_missing_include_is_an_error(self):
        files = {f"{V2}/x": "include:nope\nx.com\n"}
        with self.assertRaises(br.FetchError):
            br.parse_v2fly(f"{V2}/x", fake_fetch(files))


class BuildTag(unittest.TestCase):
    def test_add_remove_and_output_shape(self):
        files = {"https://s/a.lst": "a.com\nb.com\n", "https://s/n.lst": "192.0.2.0/24\n"}
        spec = {"sources": [{"url": "https://s/a.lst", "format": "plain"}, {"url": "https://s/n.lst", "format": "plain"}],
                "add": {"domain": ["exact.c.com"], "domain_regex": ["^r\\.c\\.com$"], "domain_suffix": ["c.com"]},
                "remove": ["b.com"]}
        rs = br.build_tag("t", spec, fake_fetch(files))
        self.assertEqual(rs["version"], br.RULESET_VERSION)
        rule = rs["rules"][0]
        self.assertEqual(rule["domain_suffix"], ["a.com", "c.com"])
        self.assertEqual(rule["domain"], ["exact.c.com"])
        self.assertEqual(rule["domain_regex"], ["^r\\.c\\.com$"])
        self.assertEqual(rule["ip_cidr"], ["192.0.2.0/24"])

    def test_add_only_tag(self):
        rs = br.build_tag("iptv", {"sources": [], "add": {"domain_suffix": ["tv.example"]}}, fake_fetch({}))
        self.assertEqual(rs["rules"][0], {"domain_suffix": ["tv.example"]})

    def test_empty_result_is_an_error(self):
        with self.assertRaises(br.SourceError):
            br.build_tag("t", {"sources": [{"url": "https://s/e.lst", "format": "plain"}]}, fake_fetch({"https://s/e.lst": "# empty\n"}))

    def test_empty_source_is_an_error_even_with_add(self):
        spec = {"sources": [{"url": "https://s/e.lst", "format": "plain"}], "add": {"domain_suffix": ["x.com"]}}
        with self.assertRaises(br.SourceError):
            br.build_tag("t", spec, fake_fetch({"https://s/e.lst": "<html>rate limited</html>\n"}))

    def test_unknown_format(self):
        with self.assertRaises(br.SourceError):
            br.build_tag("t", {"sources": [{"url": "https://s/a", "format": "srs"}]}, fake_fetch({"https://s/a": "x"}))

    def test_invalid_add_rejected(self):
        with self.assertRaises(br.SourceError):
            br.build_tag("t", {"sources": [], "add": {"domain_suffix": ["bad domain"]}}, fake_fetch({}))
        with self.assertRaises(br.SourceError):
            br.build_tag("t", {"sources": [], "add": {"domain_regex": ["(unclosed"]}}, fake_fetch({}))


class SizeGuard(unittest.TestCase):
    def test_limits(self):
        br.check_size_change("t", 100, 150)  # +50% is the limit, allowed
        br.check_size_change("t", 100, 50)
        br.check_size_change("t", 0, 10)  # no previous file
        with self.assertRaises(br.SourceError):
            br.check_size_change("t", 100, 151)
        with self.assertRaises(br.SourceError):
            br.check_size_change("t", 100, 49)


class Main(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.tmp.name, "out")
        os.makedirs(self.out)
        self.manifest = os.path.join(self.tmp.name, "sources.json")
        with open(self.manifest, "w", encoding="utf-8") as f:
            json.dump({"tags": {
                "good": {"sources": [{"url": "https://s/good.lst", "format": "plain"}]},
                "broken": {"sources": [{"url": "https://s/missing.lst", "format": "plain"}]},
            }}, f)
        self.files = {"https://s/good.lst": "".join(f"d{i}.com\n" for i in range(10))}

    def tearDown(self):
        self.tmp.cleanup()

    def read(self, tag):
        with open(os.path.join(self.out, f"{tag}.json"), encoding="utf-8") as f:
            return json.load(f)

    def write_prev(self, tag, n):
        with open(os.path.join(self.out, f"{tag}.json"), "w", encoding="utf-8") as f:
            json.dump({"version": 2, "rules": [{"domain_suffix": [f"p{i}.com" for i in range(n)]}]}, f)

    def test_broken_tag_keeps_old_file_others_written(self):
        self.write_prev("broken", 3)
        rc = br.main(["--manifest", self.manifest, "--out", self.out], fetch=fake_fetch(self.files))
        self.assertEqual(rc, 1)
        self.assertEqual(len(self.read("good")["rules"][0]["domain_suffix"]), 10)
        self.assertEqual(len(self.read("broken")["rules"][0]["domain_suffix"]), 3)

    def test_size_guard_and_force(self):
        self.write_prev("good", 100)
        rc = br.main(["--manifest", self.manifest, "--out", self.out, "--only", "good"], fetch=fake_fetch(self.files))
        self.assertEqual(rc, 1)
        self.assertEqual(len(self.read("good")["rules"][0]["domain_suffix"]), 100)
        rc = br.main(["--manifest", self.manifest, "--out", self.out, "--only", "good", "--force"], fetch=fake_fetch(self.files))
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.read("good")["rules"][0]["domain_suffix"]), 10)

    def test_unchanged_file_not_rewritten(self):
        args = ["--manifest", self.manifest, "--out", self.out, "--only", "good"]
        self.assertEqual(br.main(args, fetch=fake_fetch(self.files)), 0)
        path = os.path.join(self.out, "good.json")
        os.utime(path, (1, 1))
        self.assertEqual(br.main(args, fetch=fake_fetch(self.files)), 0)
        self.assertEqual(os.stat(path).st_mtime, 1)

    def test_output_is_stable_json(self):
        br.main(["--manifest", self.manifest, "--out", self.out, "--only", "good"], fetch=fake_fetch(self.files))
        with open(os.path.join(self.out, "good.json"), "rb") as f:
            raw = f.read()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\r", raw)


class RealManifest(unittest.TestCase):
    """The shipped manifest is well-formed and covers all published tags."""

    def test_manifest(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rulesets", "sources.json")
        with open(path, encoding="utf-8") as f:
            m = json.load(f)
        tags = m["tags"]
        self.assertEqual(len(tags), 25)
        for tag, spec in tags.items():
            for s in spec.get("sources", []):
                self.assertIn(s["format"], br.PARSERS, tag)
                self.assertTrue(s["url"].startswith("https://"), tag)
            self.assertTrue(spec.get("sources") or spec.get("add"), tag)
            br.validate_entries(tag, br.entries_from_dict(spec.get("add", {})))

    def test_ip_based_services_have_subnets(self):
        # Telegram/Discord voice/Meet connect by IP, so a domain-only ruleset is not enough
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rulesets", "sources.json")
        with open(path, encoding="utf-8") as f:
            tags = json.load(f)["tags"]
        for tag in ("telegram", "discord", "google", "meta", "twitter", "roblox"):
            urls = [s["url"] for s in tags[tag]["sources"]]
            self.assertTrue(any("/Subnets/" in u for u in urls), tag)
        self.assertIn("https://core.telegram.org/resources/cidr.txt", [s["url"] for s in tags["telegram"]["sources"]])


if __name__ == "__main__":
    unittest.main()
