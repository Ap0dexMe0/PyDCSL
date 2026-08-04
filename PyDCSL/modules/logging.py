import logging
import sys

import coloredlogs

NOTICE = logging.INFO + 5
logging.addLevelName(NOTICE, "NOTICE")


def setup_logging():
    """Configure root logger to INFO level with colored logs and a simple format."""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Set up base logging config
    logging.basicConfig(level=logging.INFO, format=log_format)

    # Add colored logs to the root logger
    coloredlogs.install(level='INFO', fmt=log_format)

    return logging


def get_report_logger(name):
    """Logger used for the clean (message-only) report output.

    The pretty-printed report (sections, key/value rows) must not be polluted
    with timestamps/level names, so it gets its own message-only handler.
    """
    log = logging.getLogger(name)
    if not log.handlers:
        _console = logging.StreamHandler(sys.stdout)
        _console.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(_console)
    log.setLevel(logging.INFO)
    log.propagate = False
    return log
