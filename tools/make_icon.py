import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dumbbell.icon import ASCII_LOGO, write_assets
from make_logo_assets import write_logo_assets


if __name__ == "__main__":
    assets = write_logo_assets()
    if assets is None:
        assets = write_assets()
        print(ASCII_LOGO)
    print(f"assets written to {assets}")
