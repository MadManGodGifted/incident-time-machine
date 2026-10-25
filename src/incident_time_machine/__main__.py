"""Module execution entrypoint: python -m src.incident_time_machine <fixture.json>"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
