"""False Positive 18: Standard logging with structured parameters."""
import logging

logger = logging.getLogger(__name__)


def log_login_event(user_id: int, success: bool) -> None:
    logger.info("User authentication event user_id=%d success=%s", user_id, success)
