#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Cut a release: version bump, generated CHANGELOG.md entry, commit and tag.

    scripts/release.py                 # next version chosen from the commits
    scripts/release.py 1.0.0           # or given explicitly
    scripts/release.py --dry-run       # only show what would be released
    scripts/release.py notes [v1.0.0]  # print a version's notes (GitHub release body)

The changelog is generated from the commits since the last `v*` tag. A commit
lands in a section by, in this order:

1. a `Changelog:` trailer - added, changed, fixed, removed, deprecated,
   security, performance, breaking, or skip (the same trailer GitLab uses);
2. a Conventional Commits prefix - `feat:`, `fix:`, `perf:`, `security:`,
   `feat!:` for a breaking change; chore/ci/test/docs/build/refactor/style are
   left out;
3. the first word of a plain subject - "Add …" is Added, "Fix …" Fixed,
   "Remove …" Removed, anything else Changed.

The next version follows Semantic Versioning: a breaking change bumps the major
version (the minor one before 1.0), anything Added the minor one, the rest the
patch. Nothing is pushed; the script prints what to run next.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
VERSION_FILE = ROOT / "app" / "__init__.py"
PACKAGE_JSON = ROOT / "frontend" / "package.json"
PACKAGE_LOCK = ROOT / "frontend" / "package-lock.json"
RELEASE_BRANCH = "main"

SECTIONS = ("Breaking changes", "Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")

TRAILER_SECTIONS = {
    "breaking": "Breaking changes",
    "added": "Added",
    "changed": "Changed",
    "performance": "Changed",
    "other": "Changed",
    "deprecated": "Deprecated",
    "removed": "Removed",
    "fixed": "Fixed",
    "security": "Security",
}
CONVENTIONAL_SECTIONS = {
    "feat": "Added",
    "fix": "Fixed",
    "perf": "Changed",
    "revert": "Changed",
    "security": "Security",
    "sec": "Security",
    "deprecate": "Deprecated",
    "remove": "Removed",
}
CONVENTIONAL_SKIPPED = {"chore", "ci", "test", "tests", "docs", "build", "refactor", "style"}
VERB_SECTIONS = {
    "Added": {"add", "adds", "added", "introduce", "introduces", "support", "supports", "allow", "allows",
              "enable", "enables", "implement", "implements", "let", "lets", "create", "creates", "notify", "notifies"},
    "Fixed": {"fix", "fixes", "fixed", "correct", "corrects", "repair", "repairs", "resolve", "resolves"},
    "Removed": {"remove", "removes", "removed", "drop", "drops", "delete", "deletes"},
    "Deprecated": {"deprecate", "deprecates"},
}

CONVENTIONAL = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<bang>!)?:\s*(?P<text>.+)$")
VERSION_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
RELEASE_SUBJECT = re.compile(r"^(?:chore\(release\):\s*)?(?:Release\s+)?v\d+\.\d+\.\d+$")


@dataclass
class Entry:
    section: str
    text: str


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def fail(message: str) -> None:
    print(f"release: {message}", file=sys.stderr)
    sys.exit(1)


# --- versions -----------------------------------------------------------------


def parse(version: str) -> tuple[int, int, int]:
    match = VERSION_TAG.match(version if version.startswith("v") else f"v{version}")
    if not match:
        fail(f"'{version}' is not a version like 1.2.3")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def current_version() -> str:
    match = re.search(r'^__version__ = "([^"]+)"$', VERSION_FILE.read_text(encoding="utf-8"), re.M)
    if not match:
        fail(f"no __version__ in {VERSION_FILE}")
    return match.group(1)


def last_tag() -> str | None:
    tags = [tag for tag in git("tag", "--merged", "HEAD", "--list", "v*").splitlines() if VERSION_TAG.match(tag)]
    return max(tags, key=parse) if tags else None


def next_version(base: str, entries: list[Entry]) -> str:
    major, minor, patch = parse(base)
    sections = {entry.section for entry in entries}
    if "Breaking changes" in sections:
        return f"{major + 1}.0.0" if major >= 1 else f"0.{minor + 1}.0"
    if "Added" in sections:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def write_version(version: str) -> None:
    text = VERSION_FILE.read_text(encoding="utf-8")
    VERSION_FILE.write_text(
        re.sub(r'^__version__ = "[^"]+"$', f'__version__ = "{version}"', text, count=1, flags=re.M),
        encoding="utf-8",
    )
    # Only the package's own version: the first occurrence in package.json, and
    # the root and packages[""] entries in the lock file - never a dependency's.
    package = PACKAGE_JSON.read_text(encoding="utf-8")
    PACKAGE_JSON.write_text(
        re.sub(r'^(  "version": )"[^"]+"', rf'\1"{version}"', package, count=1, flags=re.M), encoding="utf-8"
    )
    lock = PACKAGE_LOCK.read_text(encoding="utf-8")
    lock = re.sub(r'^(  "version": )"[^"]+"', rf'\1"{version}"', lock, count=1, flags=re.M)
    lock = re.sub(r'^(    "": \{\n(?:      .*\n)*?      "version": )"[^"]+"', rf'\1"{version}"', lock, count=1, flags=re.M)
    PACKAGE_LOCK.write_text(lock, encoding="utf-8")
    for path in (PACKAGE_JSON, PACKAGE_LOCK):
        data = json.loads(path.read_text(encoding="utf-8"))
        own = data["version"] if path == PACKAGE_JSON else data["packages"][""]["version"]
        if own != version or data["version"] != version:
            fail(f"could not set the version in {path}")


# --- commits → entries --------------------------------------------------------


def commits(since: str | None) -> list[tuple[str, str]]:
    revision = f"{since}..HEAD" if since else "HEAD"
    raw = git("log", "--no-merges", "--reverse", "--format=%s%x1f%B%x1e", revision)
    result = []
    for record in raw.split("\x1e"):
        if not record.strip():
            continue
        subject, _, message = record.strip("\n").partition("\x1f")
        result.append((subject.strip(), message))
    return result


def classify(subject: str, message: str) -> Entry | None:
    if RELEASE_SUBJECT.match(subject) or subject.lower() == "initial commit":
        return None

    trailer = re.search(r"^Changelog:\s*(\w+)\s*$", message, re.M | re.I)
    breaking = bool(re.search(r"^BREAKING[ -]CHANGE:", message, re.M))
    text, scope, section = subject, None, None

    conventional = CONVENTIONAL.match(subject)
    if conventional:
        kind = conventional["type"]
        text = conventional["text"]
        scope = conventional["scope"]
        if conventional["bang"]:
            breaking = True
        elif kind in CONVENTIONAL_SKIPPED:
            section = "skip"
        else:
            section = CONVENTIONAL_SECTIONS.get(kind, "Changed")

    if trailer:
        value = trailer.group(1).lower()
        if value == "skip":
            return None
        section = TRAILER_SECTIONS.get(value, "Changed")
    elif breaking:
        section = "Breaking changes"
    elif section == "skip":
        return None
    elif section is None:
        first = subject.split(maxsplit=1)[0].lower().strip(":,") if subject else ""
        section = next((name for name, verbs in VERB_SECTIONS.items() if first in verbs), "Changed")

    text = text.strip().rstrip(".")
    text = text[:1].upper() + text[1:]
    return Entry(section, f"**{scope}:** {text}" if scope else text)


def render(version: str, date: str, entries: list[Entry], *, first: bool) -> str:
    lines = [f"## [{version}] – {date}", ""]
    if first:
        lines += ["First public release – see the README for everything Vulnyard does.", ""]
        return "\n".join(lines)
    grouped: OrderedDict[str, list[str]] = OrderedDict((name, []) for name in SECTIONS)
    for entry in entries:
        if entry.text not in grouped[entry.section]:
            grouped[entry.section].append(entry.text)
    for name, texts in grouped.items():
        if texts:
            lines += [f"### {name}", "", *(f"- {text}" for text in texts), ""]
    if not entries:
        lines += ["Maintenance release without user-visible changes.", ""]
    return "\n".join(lines)


CHANGELOG_HEADER = """# Changelog

All notable changes to Vulnyard are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Entries are generated from the
commit history by `scripts/release.py`.

"""


def prepend(section: str) -> None:
    existing = CHANGELOG.read_text(encoding="utf-8") if CHANGELOG.exists() else CHANGELOG_HEADER
    marker = existing.find("\n## [")
    head, rest = (existing, "") if marker < 0 else (existing[: marker + 1], existing[marker + 1 :])
    body = head.rstrip("\n") + "\n\n" + section.rstrip("\n") + "\n"
    CHANGELOG.write_text(body + ("\n" + rest if rest else ""), encoding="utf-8")


def notes(version: str | None) -> str:
    if not CHANGELOG.exists():
        fail("there is no CHANGELOG.md yet")
    text = CHANGELOG.read_text(encoding="utf-8")
    wanted = (version or "").removeprefix("v")
    blocks = re.split(r"(?m)^(?=## \[)", text)[1:]
    for block in blocks:
        header = re.match(r"## \[([^\]]+)\]", block)
        if header and (not wanted or header.group(1) == wanted):
            # The heading becomes the GitHub release title; the body is the rest.
            return block.split("\n", 1)[1].strip() + "\n"
    fail(f"version {version} is not in CHANGELOG.md")
    return ""


# --- main ---------------------------------------------------------------------


def release(args: argparse.Namespace) -> None:
    tag = last_tag()
    entries = [entry for subject, message in commits(tag) if (entry := classify(subject, message))]
    first = tag is None

    if args.version:
        version = ".".join(map(str, parse(args.version)))
    elif first:
        version = current_version()
    else:
        version = next_version(tag.removeprefix("v"), entries)
    if tag and parse(version) <= parse(tag):
        fail(f"{version} is not newer than the last release {tag}")
    if git("tag", "--list", f"v{version}"):
        fail(f"tag v{version} already exists")

    section = render(version, dt.date.today().isoformat(), entries, first=first)
    print(f"Last release: {tag or 'none'} → next: v{version}\n")
    print(section)

    if args.dry_run:
        if first and entries:
            print(f"(first release: {len(entries)} earlier commits are summarised, not listed)")
        return

    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if branch != RELEASE_BRANCH:
        fail(f"releases are cut from '{RELEASE_BRANCH}', you are on '{branch}'")
    if git("status", "--porcelain"):
        fail("the working tree is not clean - commit or stash first")

    write_version(version)
    prepend(section)
    git("add", str(VERSION_FILE), str(PACKAGE_JSON), str(PACKAGE_LOCK), str(CHANGELOG))
    git("commit", "-q", "-m", f"Release v{version}")
    # verbatim: the "### Added" headings would otherwise be stripped as comments.
    git("tag", "-a", "--cleanup=verbatim", f"v{version}", "-m", f"Vulnyard v{version}\n\n{notes(version)}")

    steps = [
        (f"git push origin {RELEASE_BRANCH} v{version}", "GitLab"),
        ("scripts/publish-github.sh", "GitHub snapshot and tag"),
        (f"scripts/release.py notes v{version}", "body of the GitHub release"),
    ]
    width = max(len(command) for command, _ in steps)
    print(f"Committed and tagged v{version}. Next:")
    for command, what in steps:
        print(f"  {command.ljust(width)}   # {what}")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "notes":
        print(notes(sys.argv[2] if len(sys.argv) > 2 else None), end="")
        return
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version", nargs="?", help="explicit version, e.g. 1.0.0 (default: derived from commits)")
    parser.add_argument("--dry-run", action="store_true", help="show the next version and its changelog only")
    release(parser.parse_args())


if __name__ == "__main__":
    main()
