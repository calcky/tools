"""Check the bilingual site after `mkdocs build --strict`."""

from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import struct
import unittest
from urllib.parse import unquote, urlsplit

import markdown


ROOT = Path(__file__).resolve().parents[2]
SITE = Path(os.environ.get("DOCS_SITE_DIR", ROOT / "site"))
TOOLS = ("irqtop", "netping", "flowgen", "cttop", "netlens", "bpftrace", "nettrace", "netcap", "xpcap", "xsktop", "gomemtop")
NETLENS_REFERENCE = (
    "netlens/docs/cli",
    "netlens/docs/interfaces",
    "netlens/docs/routing",
    "netlens/docs/monitor-metrics",
    "netlens/docs/packet-path",
)
ROUTES = ("", "getting-started", *TOOLS, *NETLENS_REFERENCE)


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.lang = None
        self.links = []
        self.images = []
        self.ids = set()
        self.palette_labels = []
        self.article = []
        self.in_article = False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "html":
            self.lang = attrs.get("lang")
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs)
        if tag == "img":
            self.images.append(attrs)
        if tag == "input" and attrs.get("name") == "__palette":
            self.palette_labels.append(attrs.get("aria-label", ""))
        if tag == "article":
            self.in_article = True

    def handle_endtag(self, tag):
        if tag == "article":
            self.in_article = False

    def handle_data(self, data):
        if self.in_article:
            self.article.append(data)


def target_file(page, href):
    path = unquote(urlsplit(href).path)
    target = SITE / path.lstrip("/") if path.startswith("/") else page.parent / path
    if not path:
        return page
    return target / "index.html" if target.is_dir() else target


class BilingualSite(unittest.TestCase):
    def pages(self):
        for locale in ("zh", "en"):
            for route in ROUTES:
                prefix = Path("en") if locale == "en" else Path()
                path = SITE / prefix / route / "index.html"
                self.assertTrue(path.is_file(), str(path))
                yield locale, route, path, Document(path.read_text(encoding="utf-8"))

    def test_source_pages_are_paired(self):
        zh = {p.relative_to(ROOT / "docs/zh") for p in (ROOT / "docs/zh").rglob("*.md")}
        en = {p.relative_to(ROOT / "docs/en") for p in (ROOT / "docs/en").rglob("*.md")}
        self.assertEqual(zh, en)
        self.assertEqual(len(zh), len(ROUTES))
        for locale in ("zh", "en"):
            for tool in TOOLS:
                page = ROOT / "docs" / locale / tool / "README.md"
                self.assertLessEqual(len(page.read_text(encoding="utf-8").splitlines()), 120)
            for route in NETLENS_REFERENCE:
                page = ROOT / "docs" / locale / f"{route}.md"
                limit = 240 if route.endswith("packet-path") else 120
                self.assertLessEqual(len(page.read_text(encoding="utf-8").splitlines()), limit)

    def test_netlens_paths_cover_xdp_boundaries(self):
        for locale in ("zh", "en"):
            path = ROOT / "docs" / locale / "netlens/docs/packet-path.md"
            text = path.read_text(encoding="utf-8")
            for concept in ("native", "generic", "XDP_PASS", "XDP_DROP", "XDP_TX", "XDP_REDIRECT", "XDP_ABORTED", "DEVMAP", "CPUMAP", "XSKMAP", "AF_XDP", "UMEM", "FILL", "COMPLETION", "zero-copy", "TC ingress", "GRO", "GSO"):
                self.assertIn(concept, text, (locale, concept))

    def test_common_tasks_are_removed(self):
        for locale in ("zh", "en"):
            self.assertFalse((ROOT / "docs" / locale / "tasks.md").exists())
        for prefix in ("", "en"):
            self.assertFalse((SITE / prefix / "tasks").exists())
        for _, _, _, doc in self.pages():
            for link in doc.links:
                self.assertNotRegex(urlsplit(link["href"]).path, r"(^|/)tasks(/|\.md|$)")

    def test_nettrace_runtime_limits_are_documented(self):
        for locale in ("zh", "en"):
            text = (ROOT / "docs" / locale / "nettrace/README.md").read_text(encoding="utf-8")
            for concept in ("ARMv7", "ARM64", "trampoline", "fentry/fexit", "/sys/kernel/btf/vmlinux", "debugfs", "native XDP", "--drop"):
                self.assertIn(concept, text, (locale, concept))

    def test_netcap_runtime_requirements_are_documented(self):
        for locale in ("zh", "en"):
            text = (ROOT / "docs" / locale / "netcap/README.md").read_text(encoding="utf-8")
            for concept in ("BCC", "debugfs", "ARM64", "ARMv7", "tcpdump", "-w"):
                self.assertIn(concept, text, (locale, concept))

    def test_screenshots_are_shared_and_linked(self):
        illustrated = {"irqtop", "netping", "flowgen", "cttop", "netlens", "netlens/docs/cli"}
        for locale, route, page, doc in self.pages():
            if route in illustrated:
                self.assertEqual(len(doc.images), 1, (locale, route))
            for img in doc.images:
                self.assertTrue(img.get("alt"), (locale, route))
                self.assertIn(img["src"], [link["href"] for link in doc.links], "Screenshot must link to its full size")
                target = target_file(page, img["src"])
                self.assertEqual(target.resolve().parent, (SITE / "assets/screenshots").resolve())
                data = target.read_bytes()
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                width, height = struct.unpack(">II", data[16:24])
                self.assertGreaterEqual(width, 1200)
                self.assertGreaterEqual(height, 600)

    def test_languages_and_contextual_switch(self):
        for locale, route, page, doc in self.pages():
            with self.subTest(locale=locale, route=route):
                self.assertEqual(doc.lang, locale)
                links = {link["hreflang"]: link["href"] for link in doc.links if "hreflang" in link}
                self.assertEqual(set(links), {"zh", "en"})
                for lang, href in links.items():
                    self.assertFalse(urlsplit(href).scheme, "Language links must be relative")
                    self.assertFalse(href.startswith("/"), "Keep Read the Docs version prefixes")
                    expected = SITE / ("en" if lang == "en" else "") / route / "index.html"
                    self.assertEqual(target_file(page, href).resolve(), expected.resolve())
                text = " ".join(doc.article)
                if locale == "en":
                    self.assertIsNone(re.search(r"[\u4e00-\u9fff]", text), "English page contains Chinese")
                    self.assertTrue(all(label.startswith("Switch to ") for label in doc.palette_labels))
                else:
                    self.assertRegex(text, r"[\u4e00-\u9fff]")
                    self.assertTrue(all(label.startswith("切换") for label in doc.palette_labels))
                self.assertEqual(len(doc.palette_labels), 2)

    def test_site_links_and_anchors(self):
        for _, _, page, doc in self.pages():
            for link in doc.links:
                href = link["href"]
                parts = urlsplit(href)
                if parts.scheme or parts.netloc:
                    continue
                with self.subTest(page=str(page.relative_to(SITE)), href=href):
                    target = target_file(page, href)
                    self.assertTrue(target.is_file(), str(target))
                    if parts.fragment:
                        dest = Document(target.read_text(encoding="utf-8"))
                        self.assertIn(unquote(parts.fragment), dest.ids)

    def test_private_content_is_not_published(self):
        for _, _, _, doc in self.pages():
            text = " ".join(doc.article)
            self.assertNotRegex(text, r"\buping\b|原名|previously named")
            for link in doc.links:
                self.assertNotRegex(link["href"], r"development/|documentation/|RELEASE/|netlens/docs/(decisions|schema)/")
        for locale in ("", "en"):
            public = SITE / locale / "netlens/docs"
            self.assertEqual({p.name for p in public.iterdir()}, {Path(route).name for route in NETLENS_REFERENCE})
        for route in ("development", "documentation", "netlens/docs/decisions", "netlens/docs/schema"):
            self.assertFalse((SITE / route).exists())
            self.assertFalse((SITE / "en" / route).exists())
        self.assertFalse((SITE / "generate.py").exists())
        self.assertFalse((SITE / "hooks.py").exists())
        self.assertFalse((SITE / "tests").exists())
        self.assertFalse((SITE / "superpowers").exists())
        self.assertFalse((ROOT / "uping").exists())

    def test_download_links_are_canonical(self):
        for _, route, _, doc in self.pages():
            if route in TOOLS:
                expected = f"https://github.com/calcky/tools/releases/tag/{route}-release"
                self.assertIn(expected, [link["href"] for link in doc.links])
            for link in doc.links:
                self.assertNotRegex(link["href"], r"releases/(tag|download)/[^/]+-v\d")

    def test_tool_pages_use_installation_and_bare_commands(self):
        for locale in ("zh", "en"):
            for tool in TOOLS:
                with self.subTest(locale=locale, tool=tool):
                    text = (ROOT / "docs" / locale / tool / "README.md").read_text(encoding="utf-8")
                    heading = "## 安装" if locale == "zh" else "## Installation"
                    self.assertIn(heading, text)
                    self.assertIn(f"releases/download/{tool}-release/{tool}-linux-x86_64", text)
                    self.assertIn(f'"$HOME/.local/bin/{tool}"', text)
                    self.assertNotRegex(text, r"(?m)^## (?:构建|Build|下载|Download)\b")
                    self.assertNotRegex(text, r"(?m)^(?:sudo\s+|\./(?:bin/)?[a-z]+\s|bin/[a-z]+\s)")

    def test_readme_links(self):
        for name in ("README.md", "README.en.md"):
            page = ROOT / name
            text = page.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"\buping\b|docs/(index|getting-started|tasks)\.md")
            doc = Document(markdown.markdown(text, extensions=["tables"]))
            for link in doc.links:
                parts = urlsplit(link["href"])
                if not parts.scheme and not parts.netloc:
                    self.assertTrue((page.parent / unquote(parts.path)).is_file(), link["href"])

    def test_search_has_both_languages(self):
        data = json.loads((SITE / "search/search_index.json").read_text(encoding="utf-8"))
        for route in (*TOOLS, *NETLENS_REFERENCE):
            for prefix in ("", "en/"):
                self.assertTrue(any(row["location"].split("#")[0] == f"{prefix}{route}/" for row in data["docs"]), (prefix, route))
        chinese = next(row["text"] for row in data["docs"] if row["location"] == "irqtop/")
        self.assertIn("\u200b", chinese, "Chinese search needs word segmentation")


if __name__ == "__main__":
    unittest.main(verbosity=2)
