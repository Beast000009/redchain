import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    """
    Configuration settings for RedChain.
    Loads from environment variables or a .env file.
    """
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API Key")
    vulners_api_key: Optional[str] = Field(default=None, description="Vulners API Key")
    gemini_api_key: Optional[str] = Field(default=None, description="Google Gemini API Key")
    
    # NVD API settings
    nvd_api_key: Optional[str] = Field(default=None, description="NVD API Key (optional but recommended for rate limits)")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

class RunConfig:
    """Runtime configuration set via CLI args."""
    def __init__(self):
        self.stealth: bool = False
        self.output_format: str = "both"  # pdf, md, both

# Global settings instance
settings = Settings()
run_config = RunConfig()
