# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Application configuration read from environment variables (12-factor)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.i18n import REFERENCE_LOCALE, match_locale

# Repository/application root (the directory containing the `app` package).
APP_ROOT = Path(__file__).resolve().parent.parent

AUTH_MODES = ("none", "proxy-header")
# Language of logs and chat messages, and of the UI when the browser has no
# stored choice. The available ones are the catalogues in app/i18n.
DEFAULT_LOCALE = "cs"

DEFAULT_KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# Variables required before any scanning can happen. Missing ones do not stop
# the application: it starts, warns and disables scanning.
SCAN_CONFIG_VARIABLES = ("GITLAB_TOKEN", "DT_API_URL", "DT_API_KEY")


class Settings(BaseSettings):
    """Runtime configuration. Only DATABASE_URL is mandatory."""

    model_config = SettingsConfigDict(
        env_file=None,  # the platform/docker provides the environment
        case_sensitive=False,
        extra="ignore",
    )

    database_url: str = ""

    gitlab_url: str = "https://gitlab.com"
    gitlab_token: str = ""

    dt_api_url: str = ""
    dt_api_key: str = ""
    dt_ui_url: str = ""

    auth_mode: str = "none"
    auth_headers: str = "X-Forwarded-Email,X-Forwarded-User"

    scan_concurrency: int = 2
    scan_timeout_seconds: int = 900

    trivy_bin: str = ""
    trivy_offline: bool = False

    ca_bundle: str = ""

    #: CISA catalog of known exploited vulnerabilities; empty turns it off
    #: (for example without internet access).
    kev_feed_url: str = DEFAULT_KEV_FEED_URL

    tz: str = "UTC"
    default_locale: str = DEFAULT_LOCALE
    log_level: str = "INFO"

    @field_validator("*", mode="before")
    @classmethod
    def _strip_strings(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("database_url")
    @classmethod
    def _normalise_database_url(cls, value: str) -> str:
        """Accept postgres:// and postgresql:// and use the asyncpg driver."""
        for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
            if value.startswith(prefix):
                return value
        for prefix in ("postgresql://", "postgres://"):
            if value.startswith(prefix):
                return "postgresql+asyncpg://" + value[len(prefix) :]
        return value

    @field_validator("auth_mode")
    @classmethod
    def _known_auth_mode(cls, value: str) -> str:
        """An unknown mode must not prevent startup – fall back to `none`."""
        return value if value in AUTH_MODES else "none"

    @field_validator("default_locale")
    @classmethod
    def _known_locale(cls, value: str) -> str:
        return match_locale(value) or match_locale(DEFAULT_LOCALE) or REFERENCE_LOCALE

    @property
    def timezone_is_valid(self) -> bool:
        """Whether TZ names a real time zone."""
        try:
            ZoneInfo(self.tz)
        except (ZoneInfoNotFoundError, ValueError, KeyError):
            return False
        return True

    @property
    def timezone_name(self) -> str:
        """Time zone to actually use; UTC when TZ is not a real zone."""
        return self.tz if self.timezone_is_valid else "UTC"

    @property
    def auth_header_names(self) -> list[str]:
        return [name.strip() for name in self.auth_headers.split(",") if name.strip()]

    @property
    def effective_dt_ui_url(self) -> str:
        """URL of the Dependency-Track frontend; defaults to the API URL."""
        return (self.dt_ui_url or self.dt_api_url).rstrip("/")

    @property
    def missing_scan_config(self) -> list[str]:
        """Names of the variables needed for scanning that are not set."""
        values = {
            "GITLAB_TOKEN": self.gitlab_token,
            "DT_API_URL": self.dt_api_url,
            "DT_API_KEY": self.dt_api_key,
        }
        return [name for name in SCAN_CONFIG_VARIABLES if not values[name]]

    @property
    def source_configured(self) -> bool:
        return bool(self.gitlab_url and self.gitlab_token)

    @property
    def dtrack_configured(self) -> bool:
        return bool(self.dt_api_url and self.dt_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
