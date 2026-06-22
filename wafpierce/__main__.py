"""Package entrypoint for `python -m wafpierce` (routes through the unified CLI)."""

import sys

from .cli import main


if __name__ == '__main__':
    sys.exit(main())
