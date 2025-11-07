import logging
import pytest
import importlib

import mlkem


def test_version_is_string():
    assert isinstance(mlkem.__version__, str)
    assert mlkem.__version__ != ""


def test_configure_logging_sets_level_and_handler():
    logger = logging.getLogger("mlkem")
    # remove existing handlers to make the test deterministic
    for h in list(logger.handlers):
        logger.removeHandler(h)

    mlkem.configure_logging(logging.DEBUG)
    assert logger.level == logging.DEBUG
    assert len(logger.handlers) >= 1


def test_all_contains_expected_exports():
    expected = {"__version__", "configure_logging", "core", "kem", "params", "utils", "api"}
    assert set(mlkem.__all__).issuperset(expected)


def test_missing_attribute_raises_attribute_error():
    with pytest.raises(AttributeError):
        _ = mlkem.__this_attribute_should_not_exist__
