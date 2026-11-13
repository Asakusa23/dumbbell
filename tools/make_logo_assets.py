from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageOps

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "dumbbell" / "assets"
BACKGROUND = (0, 0, 0, 255)
HEADER_SIZE = (240, 160)
HEADER_RADIUS = 28
ICON_SIZE = (256, 256)
ICO_SIZES = ((16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256))


def _fit(image: Image.Image, size: tuple[int, int]) -> Image.Image:
    canvas = Image.new("RGBA", size, BACKGROUND)
    contained = ImageOps.contain(image, size, Image.Resampling.LANCZOS)
    offset = ((size[0] - contained.width) // 2, (size[1] - contained.height) // 2)
    canvas.alpha_composite(contained, offset)
    return canvas


def _round_corners(image: Image.Image, radius: int) -> Image.Image:
    mask = Image.new("L", image.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, image.width - 1, image.height - 1), radius=radius, fill=255)
    rounded = Image.new("RGBA", image.size, BACKGROUND)
    rounded.paste(image, (0, 0), mask)
    return rounded


def write_logo_assets(directory: str | Path | None = None) -> Path | None:
    assets = Path(directory) if directory is not None else ASSETS
    logo_path = assets / "logo.png"
    if not logo_path.is_file():
        return None
    with Image.open(logo_path) as source:
        logo = source.convert("RGBA")
        header = _round_corners(_fit(logo, HEADER_SIZE), HEADER_RADIUS)
        header.save(assets / "logo_header.png")
        icon = _fit(logo, ICON_SIZE)
        icon.save(assets / "icon.png")
        icon.save(assets / "icon.ico", format="ICO", sizes=list(ICO_SIZES))
    return assets


if __name__ == "__main__":
    written = write_logo_assets()
    if written is None:
        print("logo.png not found, nothing to do")
    else:
        print(f"logo assets written to {written}")
