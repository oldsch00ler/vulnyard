# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Translation catalogues (SPEC 15).

Every key used in the code must exist in the reference catalogue (English),
and every other catalogue - shipped or contributed - must fit it: no keys the
reference does not know, and the same placeholders in every message, so that a
translation can never drop a value or break rendering. A contributed catalogue
may be incomplete (the missing texts fall back to English); the shipped ones
must be complete.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.config import APP_ROOT
from app.i18n import REFERENCE_LOCALE, resolve_locale, t

BACKEND_DIR = APP_ROOT / "app" / "i18n"
FRONTEND_DIR = APP_ROOT / "frontend" / "src" / "i18n" / "locales"

#: Catalogues that ship with the application and must be complete.
COMPLETE_LOCALES = ("cs", "en")

# t("code", ...) / t('code', ...) with a literal key.
KEY_PATTERN = re.compile(r"""\bt\(\s*['"]([a-zA-Z0-9_.]+)['"]""")

# i18next plural suffixes: banner.x_one / banner.x_other resolve from banner.x.
# Languages use different sets (English: one/other; Czech: one/few/many/other).
PLURAL_SUFFIXES = ("_zero", "_one", "_two", "_few", "_many", "_other")

BACKEND_PLACEHOLDER = re.compile(r"\{(\w+)\}")
FRONTEND_PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def _catalogues(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.json"))


def _backend(locale: str) -> dict[str, str]:
    return json.loads((BACKEND_DIR / f"{locale}.json").read_text(encoding="utf-8"))


def _frontend(locale: str) -> dict[str, str]:
    return _flatten(json.loads((FRONTEND_DIR / f"{locale}.json").read_text(encoding="utf-8")))


# --- keys used in the code ----------------------------------------------------


def test_backend_message_codes_exist() -> None:
    catalog = _backend(REFERENCE_LOCALE)
    used = _collect_keys(APP_ROOT / "app", ("*.py",))

    missing = sorted(code for code in used if code not in catalog)
    assert not missing, f"missing codes in app/i18n/{REFERENCE_LOCALE}.json: {missing}"


def test_frontend_translation_keys_exist() -> None:
    catalog = _frontend(REFERENCE_LOCALE)
    used = _collect_keys(APP_ROOT / "frontend" / "src", ("*.ts", "*.tsx"))

    missing = sorted(key for key in used if not _resolves(key, catalog))
    assert not missing, f"missing keys in frontend {REFERENCE_LOCALE}.json: {missing}"


# --- every catalogue against the reference ------------------------------------


@pytest.mark.parametrize("path", _catalogues(BACKEND_DIR), ids=lambda path: f"backend-{path.stem}")
def test_backend_catalogue_fits_the_reference(path: Path) -> None:
    reference = _backend(REFERENCE_LOCALE)
    catalog = json.loads(path.read_text(encoding="utf-8"))

    _assert_fits(path, catalog, reference, BACKEND_PLACEHOLDER, plural=False)


@pytest.mark.parametrize("path", _catalogues(FRONTEND_DIR), ids=lambda path: f"frontend-{path.stem}")
def test_frontend_catalogue_fits_the_reference(path: Path) -> None:
    reference = _frontend(REFERENCE_LOCALE)
    catalog = _flatten(json.loads(path.read_text(encoding="utf-8")))

    assert catalog.get("language.name"), f"{path.name}: language.name (the language's own name) is required"
    _assert_fits(path, catalog, reference, FRONTEND_PLACEHOLDER, plural=True)


def _assert_fits(
    path: Path,
    catalog: dict[str, str],
    reference: dict[str, str],
    placeholder: re.Pattern[str],
    *,
    plural: bool,
) -> None:
    def base(key: str) -> str:
        if plural:
            for suffix in PLURAL_SUFFIXES:
                if key.endswith(suffix):
                    return key[: -len(suffix)]
        return key

    reference_bases: dict[str, set[str]] = {}
    for key, text in reference.items():
        reference_bases.setdefault(base(key), set()).update(placeholder.findall(text))

    unknown = sorted(key for key in catalog if base(key) not in reference_bases)
    assert not unknown, f"{path.name}: keys the reference does not know: {unknown}"

    wrong = sorted(
        key
        for key, text in catalog.items()
        if set(placeholder.findall(text)) - reference_bases[base(key)]
    )
    assert not wrong, f"{path.name}: placeholders the reference does not have: {wrong}"

    # Dropping a placeholder loses a value; plural forms may legitimately omit
    # {{count}} ("one project" in some languages), so that is checked per base.
    catalog_bases: dict[str, set[str]] = {}
    for key, text in catalog.items():
        catalog_bases.setdefault(base(key), set()).update(placeholder.findall(text))
    dropped = sorted(
        key
        for key, names in catalog_bases.items()
        if (reference_bases[key] - {"count"}) - names
    )
    assert not dropped, f"{path.name}: messages missing a placeholder of the reference: {dropped}"

    if path.stem in COMPLETE_LOCALES:
        missing = sorted(set(reference_bases) - set(catalog_bases))
        assert not missing, f"{path.name}: shipped catalogue is incomplete: {missing}"


# --- runtime behaviour --------------------------------------------------------


def test_missing_message_falls_back_to_the_reference() -> None:
    assert t("error.not_found", "xx") == _backend(REFERENCE_LOCALE)["error.not_found"]


def test_locale_resolution_follows_accept_language() -> None:
    assert resolve_locale("en-GB,en;q=0.9", "cs") == "en"
    assert resolve_locale("CS", "en") == "cs"
    assert resolve_locale("xx-YY, xx;q=0.8", "cs") == "cs"
    assert resolve_locale(None, "unknown") == REFERENCE_LOCALE


# --- helpers ------------------------------------------------------------------


def _collect_keys(root: Path, patterns: tuple[str, ...]) -> set[str]:
    keys: set[str] = set()
    for pattern in patterns:
        for path in root.rglob(pattern):
            keys.update(KEY_PATTERN.findall(path.read_text(encoding="utf-8")))
    # Keys without a dot are local helpers/variables, not catalogue keys.
    return {key for key in keys if "." in key}


def _flatten(node: object, prefix: str = "") -> dict[str, str]:
    flat: dict[str, str] = {}
    if isinstance(node, dict):
        for key, value in node.items():
            flat.update(_flatten(value, f"{prefix}{key}."))
    elif isinstance(node, str):
        flat[prefix.rstrip(".")] = node
    return flat


def _resolves(key: str, catalog: dict[str, str]) -> bool:
    return key in catalog or any(f"{key}{suffix}" in catalog for suffix in PLURAL_SUFFIXES)
