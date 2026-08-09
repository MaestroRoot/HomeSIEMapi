from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import quote_plus

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# .../backend/app/core/config.py -> .../backend
BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Settings zote zinatoka kwenye environment / faili `.env`."""

    model_config = SettingsConfigDict(
        # Path kamili, sio ".env" tu, ili server ifanye kazi hata ikianzishwa
        # kutoka directory nyingine.
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- App ------------------------------------------------------------
    app_name: str = "HomeSIEM API"
    env: Literal["development", "staging", "production"] = "development"
    debug: bool = True
    api_v1_prefix: str = "/api/v1"

    # NoDecode: bila hii pydantic-settings inajaribu json.loads() kwenye value
    # ya .env kabla validator yetu haijafika, na "a,b" si JSON halali.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "http://localhost:5180",
            "http://localhost:3000",
            "https://homesiem.vercel.app",
        ]
    )

    # --- Postgres -------------------------------------------------------
    postgres_host: str = "localhost"
    postgres_port: int = 5433
    postgres_user: str = "homesiem"
    postgres_password: str = "homesiem"
    postgres_db: str = "homesiem"

    # --- Firebase -------------------------------------------------------
    firebase_credentials_file: str | None = None
    firebase_project_id: str | None = None

    # --- AI (Groq) ------------------------------------------------------
    groq_api_key: str | None = None
    groq_model: str = "llama-3.3-70b-versatile"

    # --- Threat intel (AlienVault OTX) ----------------------------------
    otx_api_key: str | None = None

    # --- GeoIP (MaxMind GeoLite2) ---------------------------------------
    #: Credentials za kupakua .mmdb pekee, hazitumiki wakati wa lookup.
    maxmind_account_id: str | None = None
    maxmind_license_key: str | None = None
    geoip_db_dir: str = "./data/geoip"

    # --- Packet analysis (tshark) ---------------------------------------
    #: Path kamili ya tshark. PATH ya Windows si ya kutegemewa, na server
    #: inaweza kuanzishwa popote, hivyo tunaweka path wazi.
    tshark_path: str = r"C:\Program Files\Wireshark\tshark.exe"
    #: Kikomo cha faili ya pcap kwa upload wa synchronous. Kubwa zaidi
    #: itahitaji job queue (background), haijaandikwa bado. Overridable kwa
    #: env PCAP_MAX_BYTES (idadi ya bytes).
    pcap_max_bytes: int = 200 * 1024 * 1024
    #: Kikomo cha packets tshark itasoma, ulinzi dhidi ya pcap ya kuvuruga.
    #: Overridable kwa env PCAP_MAX_PACKETS.
    pcap_max_packets: int = 1_000_000
    #: Muda tshark inaruhusiwa kufanya kazi kabla ya kukatwa (sekunde).
    #: Imeongezwa kuhimili pcap kubwa (packets nyingi). Overridable: TSHARK_TIMEOUT.
    tshark_timeout: float = 180.0

    # --- Email (Brevo) --------------------------------------------------
    brevo_api_key: str | None = None
    brevo_sender_email: str = "maestrobusiness@aol.com"
    brevo_sender_name: str = "HomeSIEM"
    #: Inatumika kwenye links za invite kwenye email.
    app_public_url: str = "http://localhost:5180"

    # --- Payments (ClickPesa) -------------------------------------------
    #: Zikiwepo zote mbili, ClickPesaGateway inatumika badala ya ManualGateway.
    clickpesa_client_id: str | None = None
    clickpesa_api_key: str | None = None
    clickpesa_base_url: str = "https://api.clickpesa.com"
    #: Siri inayowekwa mwishoni mwa webhook URL kama ulinzi wa ziada.
    clickpesa_webhook_secret: str | None = None

    # --- Payments (PesaPal) ----------------------------------------------
    #: PesaPal API 3.0 credentials. Consumer key/secret hutoka kwenye
    #: merchant dashboard: https://www.pesapal.com/dashboard
    pesapal_consumer_key: str | None = None
    pesapal_consumer_secret: str | None = None
    pesapal_mode: Literal["sandbox", "live"] = "sandbox"
    #: IPN (Instant Payment Notification) URL. PesaPal inatuma status updates
    #: kwenye hii URL. Lazima iwe publicly accessible.
    pesapal_ipn_url: str | None = None
    #: IPN ID ya PesaPal (IPN registration inapata hii). Lazima iwekwe
    #: kabla ya SubmitOrderRequest.
    pesapal_ipn_id: str | None = None
    #: Webhook secret for additional security (optional).
    pesapal_webhook_secret: str | None = None

    # --- NextDNS (reseller model) -----------------------------------------
    #: NextDNS API key (my.nextdns.io > Account > API key). Single key inatumika
    #: kuunda/manage profile per org — watumiaji hawapati hii, wao wanapata
    #: domain + QR pekee kutoka dashboard.
    nextdns_api_key: str | None = None
    #: NextDNS account ID (mfano "5f4959"), inatumika kwenye maandiko/UI tu.
    nextdns_account_id: str | None = None

    @property
    def clickpesa_ready(self) -> bool:
        return bool(self.clickpesa_client_id and self.clickpesa_api_key)

    @property
    def pesapal_ready(self) -> bool:
        return bool(self.pesapal_consumer_key and self.pesapal_consumer_secret)

    @property
    def nextdns_ready(self) -> bool:
        return bool(self.nextdns_api_key)

    # --- Password reset OTP ---------------------------------------------
    otp_ttl_minutes: int = 10
    otp_max_attempts: int = 5

    # --- Dev bypass -----------------------------------------------------
    auth_dev_bypass: bool = False

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Inaruhusu CORS_ORIGINS=a,b,c kama string moja kwenye .env."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def groq_enabled(self) -> bool:
        return bool(self.groq_api_key)

    @property
    def otx_enabled(self) -> bool:
        return bool(self.otx_api_key)

    @property
    def geoip_dir(self) -> Path:
        """Path kamili, ili server ifanye kazi ikianzishwa popote."""
        raw = Path(self.geoip_db_dir)
        return raw if raw.is_absolute() else (BACKEND_DIR / raw).resolve()

    @property
    def maxmind_download_enabled(self) -> bool:
        """Tunaweza kupakua/kusasisha .mmdb. Si sawa na kuwa nazo tayari."""
        return bool(self.maxmind_account_id and self.maxmind_license_key)

    @property
    def geoip_enabled(self) -> bool:
        """Kuwa na key hakutoshi, lookup inahitaji faili yenyewe ipo diski."""
        return (self.geoip_dir / "GeoLite2-City.mmdb").is_file()

    @property
    def tshark_available(self) -> bool:
        return Path(self.tshark_path).is_file()

    @property
    def email_enabled(self) -> bool:
        return bool(self.brevo_api_key)

    @property
    def dev_bypass_enabled(self) -> bool:
        """Bypass haiwezi kuwashwa production hata kama .env inasema hivyo."""
        return self.auth_dev_bypass and not self.is_production

    @property
    def database_url(self) -> str:
        # URL-encode user/password/db ili herufi maalum (@ : / # % nk kwenye
        # password imara) zisivunje connection string na kusababisha asyncpg
        # ijaribu kutafsiri "host" isiyo sahihi ("Name or service not known").
        user = quote_plus(self.postgres_user)
        password = quote_plus(self.postgres_password)
        db = quote_plus(self.postgres_db)
        return (
            f"postgresql+asyncpg://{user}:{password}"
            f"@{self.postgres_host}:{self.postgres_port}/{db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
