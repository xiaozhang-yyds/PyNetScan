def pytest_addoption(parser):
    parser.addoption(
        "--online", action="store_true", default=False,
        help="enable tests that require internet access"
    )

def pytest_configure(config):
    import pytest
    pytest.config = config  # 让其他文件也能访问 config
