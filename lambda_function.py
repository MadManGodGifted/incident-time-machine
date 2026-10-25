"""Root entrypoint for AWS Lambda deployments.

Exposes lambda_handler conforming to the standard AWS Lambda convention:
`lambda_function.lambda_handler`
"""

from src.incident_time_machine.lambda_handler import lambda_handler

__all__ = ["lambda_handler"]
