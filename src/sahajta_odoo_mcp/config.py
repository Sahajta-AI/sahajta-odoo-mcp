"""Runtime settings, read from environment variables (or a .env file).

Every safety-relevant setting defaults to the most restrictive value. An admin has
to opt in, explicitly, to anything that changes data.
"""

from __future__ import annotations

from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Hard ceilings that no environment variable can raise.
HARD_MAX_READ_RECORDS = 1000
HARD_MAX_WRITE_RECORDS = 100
HARD_MAX_ACTION_RECORDS = 100
# How long a person's approval of a previewed change stays usable (the staleness check applies on top).
DEFAULT_CONFIRM_TTL_SECONDS = 3600
HARD_MAX_CONFIRM_TTL_SECONDS = 24 * 3600

DEFAULT_REDIRECT_URIS = [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "http://localhost:*",
    "http://127.0.0.1:*",
]

CsvList = Annotated[list[str], NoDecode]


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Odoo connection -------------------------------------------------------
    odoo_url: str = Field(description="Base URL of the Odoo instance, e.g. https://sahajta.odoo.com")
    odoo_db: str | None = Field(default=None, description="Database name. Required for the legacy JSON-RPC protocol.")
    odoo_protocol: Literal["auto", "json2", "jsonrpc"] = "auto"
    odoo_timeout_seconds: float = 30.0
    odoo_verify_tls: bool = True
    # Odoo Online's acceptable-use policy: throttled, non-parallel API calls. Raise only for Odoo.sh/on-premise.
    odoo_max_parallel_requests: int = Field(default=1, ge=1, le=16)
    # Only used in stdio (local) mode. In HTTP mode every person signs in with their own key.
    odoo_login: str | None = None
    odoo_api_key: SecretStr | None = None

    # --- What the AI may do ------------------------------------------------------
    mcp_access_mode: Literal["read_only", "read_write"] = "read_only"
    mcp_require_preview: bool = True
    mcp_allow_archive: bool = False
    mcp_allow_cancel_actions: bool = False
    mcp_allow_outbound_messages: bool = False
    mcp_admin_contact: str = Field(
        default="your administrator", description="Who people should ask to switch something on for Claude; named in refusals."
    )
    mcp_default_read_limit: int = Field(default=50, ge=1)
    mcp_max_read_records: int = Field(default=200, ge=1)
    # creating and editing records, and moving files
    mcp_max_write_records: int = Field(default=100, ge=1)
    # buttons, dialogs, sending messages, followers and deleting: each acts on whole records at once
    mcp_max_action_records: int = Field(default=20, ge=1)
    mcp_confirm_ttl_seconds: int = Field(
        default=DEFAULT_CONFIRM_TTL_SECONDS, ge=60, description="How long an approved preview stays usable."
    )
    mcp_max_text_chars: int = Field(default=4000, ge=200)
    mcp_max_response_chars: int = Field(default=120_000, ge=10_000)
    mcp_blocked_models: CsvList = Field(default_factory=list, description="Extra models to block entirely.")
    mcp_readonly_models: CsvList = Field(default_factory=list, description="Extra models that may be read but never changed.")
    mcp_writable_models: CsvList = Field(
        default_factory=list, description="If set, ONLY these models may be changed (allowlist)."
    )
    mcp_blocked_methods: CsvList = Field(default_factory=list, description="Extra method names/patterns to block.")
    mcp_extra_allowed_methods: CsvList = Field(
        default_factory=list,
        description="'model:method' pairs callable even though they are not a button in the Odoo UI.",
    )
    mcp_reads_per_minute: int = Field(default=120, ge=1)
    mcp_writes_per_minute: int = Field(default=30, ge=1)
    mcp_audit_log_file: str | None = None
    mcp_default_timezone: str = Field(
        default="UTC", description="Time zone used when the Odoo user has none set, e.g. Asia/Kolkata."
    )

    # --- HTTP / connector mode --------------------------------------------------------
    mcp_public_url: str | None = Field(default=None, description="Public https URL of this server, e.g. https://odoo-mcp.sahajta.ai")
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_secret: SecretStr | None = Field(default=None, description="Long random secret used to sign and encrypt tokens.")
    mcp_admin_token: SecretStr | None = Field(
        default=None, description="Bearer token for GET /admin/usage (usage report). Unset = report disabled."
    )
    mcp_data_dir: str = "./data"
    mcp_allowed_redirect_uris: CsvList = Field(default_factory=lambda: list(DEFAULT_REDIRECT_URIS))
    mcp_allowed_login_domains: CsvList = Field(
        default_factory=list, description="If set, only Odoo logins ending in these domains may connect, e.g. sahajta.ai"
    )
    mcp_allowed_logins: CsvList = Field(
        default_factory=list, description="If set, only these exact Odoo logins may connect (checked with the domains)."
    )
    # Shared state for serverless hosting (Vercel + Upstash sets REDIS_URL / KV_URL automatically).
    mcp_redis_url: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("mcp_redis_url", "MCP_REDIS_URL", "REDIS_URL", "KV_URL")
    )
    mcp_cimd_allowed_hosts: CsvList = Field(
        default_factory=lambda: ["claude.ai", "claude.com"],
        description="Hosts whose OAuth Client ID Metadata Documents are trusted.",
    )
    mcp_access_token_ttl_seconds: int = Field(default=3600, ge=300)
    mcp_refresh_token_ttl_seconds: int = Field(default=30 * 24 * 3600, ge=3600)
    mcp_trust_proxy_headers: bool = False

    _split = field_validator(
        "mcp_blocked_models",
        "mcp_readonly_models",
        "mcp_writable_models",
        "mcp_blocked_methods",
        "mcp_extra_allowed_methods",
        "mcp_allowed_redirect_uris",
        "mcp_allowed_login_domains",
        "mcp_allowed_logins",
        "mcp_cimd_allowed_hosts",
        mode="before",
    )(_split_csv)

    @field_validator("odoo_url")
    @classmethod
    def _normalise_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith(("https://", "http://")):
            raise ValueError("ODOO_URL must start with https://")
        return value

    @field_validator("mcp_default_timezone")
    @classmethod
    def _check_timezone(cls, value: str) -> str:
        value = value.strip() or "UTC"
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"MCP_DEFAULT_TIMEZONE {value!r} is not a time zone name such as Asia/Kolkata") from exc
        return value

    @model_validator(mode="after")
    def _clamp(self) -> Settings:
        self.mcp_max_read_records = min(self.mcp_max_read_records, HARD_MAX_READ_RECORDS)
        self.mcp_max_write_records = min(self.mcp_max_write_records, HARD_MAX_WRITE_RECORDS)
        self.mcp_max_action_records = min(self.mcp_max_action_records, HARD_MAX_ACTION_RECORDS)
        self.mcp_confirm_ttl_seconds = min(self.mcp_confirm_ttl_seconds, HARD_MAX_CONFIRM_TTL_SECONDS)
        self.mcp_default_read_limit = min(self.mcp_default_read_limit, self.mcp_max_read_records)
        return self

    @property
    def read_write(self) -> bool:
        return self.mcp_access_mode == "read_write"

    def require_http_settings(self) -> None:
        problems = []
        if not self.mcp_public_url or not self.mcp_public_url.startswith("https://"):
            if not (self.mcp_public_url or "").startswith(("http://localhost", "http://127.0.0.1")):
                problems.append("MCP_PUBLIC_URL must be the public https:// URL of this server")
        if not self.mcp_secret or len(self.mcp_secret.get_secret_value()) < 32:
            problems.append("MCP_SECRET must be set to a random string of at least 32 characters")
        if not self.odoo_url.startswith("https://") and not self.odoo_url.startswith(("http://localhost", "http://127.0.0.1")):
            problems.append("ODOO_URL must use https:// so API keys are never sent in clear text")
        if problems:
            raise SystemExit("Configuration error:\n  - " + "\n  - ".join(problems))

    def require_stdio_settings(self) -> None:
        problems = []
        if not self.odoo_login:
            problems.append("ODOO_LOGIN is required (the Odoo user's login email)")
        if not self.odoo_api_key:
            problems.append("ODOO_API_KEY is required (create one in Odoo: My Preferences > Security > Create API Key)")
        if problems:
            raise SystemExit("Configuration error:\n  - " + "\n  - ".join(problems))
