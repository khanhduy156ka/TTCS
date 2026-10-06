from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


class Settings(BaseSettings):
    # Cau hinh Wazuh Indexer
    wazuh_indexer_url: str
    wazuh_indexer_user: str
    wazuh_indexer_password: str
    wazuh_verify_ssl: bool = False

    # Provider mac dinh, tung profile co the override rieng de chay hybrid
    llm_provider: str = "ollama"

    llm_fast_provider: str | None = None
    llm_reasoning_provider: str | None = None

    # Giu legacy settings de tuong thich cau hinh cu
    llm_fast_model: str | None = None
    llm_reasoning_model: str | None = None

    # Cau hinh Ollama
    ollama_model: str = "qwen3.5:9b"
    ollama_base_url: str = "http://localhost:11434"
    ollama_fast_model: str | None = None
    ollama_reasoning_model: str | None = None

    # Cau hinh Gemini
    gemini_api_key: str | None = None
    gemini_model: str | None = None
    gemini_fast_model: str | None = None
    gemini_reasoning_model: str | None = None

    # Cau hinh VirusTotal
    virustotal_api_key: str | None = None
    virustotal_base_url: str = (
        "https://www.virustotal.com/api/v3"
    )

    # Cau hinh PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "soc_multi_agent"
    postgres_user: str = "soc_app"
    postgres_password: str

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
