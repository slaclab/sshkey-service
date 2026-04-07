import logging
import pytest
from loguru import logger


@pytest.fixture(autouse=True)
def propagate_loguru(caplog):
    """Forward loguru output to Python's standard logging so pytest caplog captures it."""
    handler_id = logger.add(caplog.handler, format="{message}", level="WARNING")
    with caplog.at_level(logging.WARNING):
        yield
    logger.remove(handler_id)
