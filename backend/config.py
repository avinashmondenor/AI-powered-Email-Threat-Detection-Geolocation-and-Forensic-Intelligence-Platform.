import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    PROJECT_NAME: str = "Email Threat Detection Platform"
    VERSION: str = "1.0.0"
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "email_threats.db")
    USE_MOCK_INTELLIGENCE: bool = os.getenv("USE_MOCK_INTELLIGENCE", "true").lower() in ("true", "1", "yes")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit

settings = Settings()
