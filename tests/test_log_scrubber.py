import io
import logging

from src.utils.log_scrubber import SensitiveDataFilter, install_scrubber


def test_filter_scrubs_ip_and_token() -> None:
    stream = io.StringIO()
    logger = logging.getLogger("scrubber-test")
    logger.handlers.clear()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.addFilter(SensitiveDataFilter())

    logger.info("scan of 192.168.1.50 with Authorization: Bearer abc.def.ghi")

    out = stream.getvalue()
    assert "192.168.1.50" not in out
    assert "abc.def.ghi" not in out
    assert "[REDACTED_IP]" in out
    assert "[REDACTED_TOKEN]" in out


def test_install_scrubber_idempotent() -> None:
    root = logging.getLogger("scrubber-idem")
    root.filters.clear()
    install_scrubber(root)
    install_scrubber(root)
    count = sum(isinstance(f, SensitiveDataFilter) for f in root.filters)
    assert count == 1
