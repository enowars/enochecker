import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--with_nosqldict", action="store_true", help="Run the tests with the nosqldict"
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "nosqldict: mark test as requiring MongoDB")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--with_nosqldict"):
        return
    skip_nosqldict = pytest.mark.skip(reason="need --with_nosqldict option to run")
    for item in items:
        if "nosqldict" in item.keywords:
            item.add_marker(skip_nosqldict)
