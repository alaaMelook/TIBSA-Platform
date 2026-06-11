"""
Application configuration using pydantic-settings.
Loads values from environment variables / .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    # ─── Supabase ─────────────────────────────────────────────
    supabase_url: str = ""
    supabase_service_role_key: str = ""

    # ─── VirusTotal ────────────────────────────────────────────
    virustotal_api_key: str = ""
    otx_api_key: str = ""  # AlienVault OTX API key

    # ─── Infra Intelligence APIs ───────────────────────────────
    abuseipdb_api_key: str = ""  # https://www.abuseipdb.com/api
    abuse_ch_api_key: str = ""  # https://auth.abuse.ch/ (URLhaus & ThreatFox)

    # ─── CORS ─────────────────────────────────────────────────
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # ─── Malice Docker AV ─────────────────────────────────────
    malice_engines: str = ""
    malice_container_timeout: int = 120
    malice_helper_image: str = "alpine:latest"

    # ─── OpenRouter AI ────────────────────────────────────────
    ai_provider: str = "openrouter"
    openrouter_api_key: str = ""
    openrouter_model: str = "moonshotai/kimi-k2.6:free"
    openrouter_max_tokens: int = 800

    # ─── Gemini AI ────────────────────────────────────────────
    gemini_api_key: str = ""

    # ─── App ──────────────────────────────────────────────────
    app_name: str = "TIBSA API"
    debug: bool = False
    demo_mode: bool = False
    enable_strict_correlation_hardening: bool = True

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",")]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

TRUSTED_PROVIDERS = {
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "microsoft.com",
    "amazon.com",
    "apple.com",
    "github.com",
    "linkedin.com",
    "cloudflare.com"
}
