"""Backward-compatibility stub. CLI has moved to artiforge/cli.py.

Use:  python -m artiforge <command>
      python artiforge/cli.py <command>   (direct)
"""
from artiforge.cli import main  # noqa: F401

if __name__ == "__main__":
    main()
