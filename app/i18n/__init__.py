# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Message catalogues for the backend.

User facing texts (log messages, API error messages, chat notifications) are
never written inline in the code: the code works with codes plus parameters and
the text is rendered from a catalogue.

Adding a language means adding `app/i18n/<locale>.json` - nothing else. The
locale is the file name (`de`, `pt-BR`); every catalogue found here is offered
to clients. A catalogue may be incomplete: a missing message falls back to the
reference catalogue (English), so a partial translation is already useful.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

CATALOG_DIR = Path(__file__).resolve().parent

#: Complete catalogue every other one is checked against and falls back to.
REFERENCE_LOCALE = "en"


@lru_cache
def available_locales() -> tuple[str, ...]:
    return tuple(sorted(path.stem for path in CATALOG_DIR.glob("*.json")))


def match_locale(value: str | None) -> str | None:
    """The available locale `value` names, ignoring case (`pt-br` → `pt-BR`)."""
    if not value:
        return None
    wanted = value.strip().replace("_", "-").lower()
    for locale in available_locales():
        if locale.lower() == wanted:
            return locale
    return None


@lru_cache
def catalog(locale: str) -> dict[str, str]:
    """The messages of one locale as written in its file; {} when there is none."""
    path = CATALOG_DIR / f"{locale}.json"
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def t(code: str, locale: str = REFERENCE_LOCALE, /, **params: object) -> str:
    """Render the message `code` in `locale`.

    `code` and `locale` are positional-only so that any parameter name (even
    "code" or "locale") can be used in a message.

    An unknown code or a missing parameter never raises: the code itself is
    returned instead, so a typo cannot take the application down. A message
    missing in `locale` is taken from the reference catalogue.
    """
    template = catalog(locale).get(code)
    if template is None:
        template = catalog(REFERENCE_LOCALE).get(code)
    if template is None:
        return code
    try:
        return template.format(**params)
    except (KeyError, IndexError):
        return template


def resolve_locale(accept_language: str | None, default: str) -> str:
    """Pick a locale from the Accept-Language header (SPEC section 15).

    Falls back to `default` (DEFAULT_LOCALE) when the header is missing or
    asks for a language we do not have a catalogue for. A regional tag falls
    back to its language (`de-AT` → `de`).
    """
    if accept_language:
        for part in accept_language.split(","):
            tag = part.split(";")[0].strip()
            if not tag or tag == "*":
                continue
            for candidate in (tag, tag.split("-")[0]):
                matched = match_locale(candidate)
                if matched:
                    return matched
    return match_locale(default) or REFERENCE_LOCALE
