# flake8: noqa: E203,E501,W503
# pylint: disable=C0413,W0718,R0903,R0801
# mypy: disable-error-code=unused-awaitable
"""secflow WSGI runner."""

from secflow.app import create_app

application = create_app()
