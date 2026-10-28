"""False Positive 11: Environment variable lookup for API key without hardcoding."""
import os


def get_service_api_key() -> str:
    api_key = os.environ.get("APP_SERVICE_API_KEY")
    if not api_key:
        raise RuntimeError("Missing required APP_SERVICE_API_KEY environment variable")
    return api_key
