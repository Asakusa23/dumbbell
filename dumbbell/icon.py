from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path
from typing import Callable

ASCII_LOGO = "\n".join(
    [
        " .-----.        .-----. ",
        "/  ___  \\      /  ___  \\",
        "| /###\\ |------| /###\\ |",
        "| |###| |======| |###| |",
        "| \\###/ |------| \\###/ |",
        "\\  '--' /      \\  '--' /",
        " '-----'        '-----' ",
    ]
)

_BASE_SIZE = 256
_OUTER_SQUARE = (128, 128, 120, 120, 0)
_INNER_SQUARE = (128, 128, 116, 116, 0)
_DUMBBELL = (
    (80, 128, 22, 66, 8),
    (176, 128, 22, 66, 8),
    (128, 128, 48, 14, 7),
    (42, 128, 10, 42, 5),
    (214, 128, 10, 42, 5),
)
_DUMBBELL_SHADOW = tuple((cx + 5, cy + 7, hw + 3, hh + 3, r) for cx, cy, hw, hh, r in _DUMBBELL)
Shade = Callable[[float, float, float, float, float, float, float], int]


def _sdf_round_rect(px: float, py: float, cx: float, cy: float, hw: float, hh: float, r: float) -> float:
    qx = abs(px - cx) - (hw - r)
    qy = abs(py - cy) - (hh - r)
    ax = qx if qx > 0 else 0.0
    ay = qy if qy > 0 else 0.0
    return math.hypot(ax, ay) + min(max(qx, qy), 0.0) - r


def _outer_shade(px: float, py: float, cx: float, cy: float, hw: float, hh: float, d: float) -> int:
    t = (py - (cy - hh)) / (2 * hh) if hh else 0.5
    value = 255.0 - 55.0 * t
    if d > -3.0:
        value += 12.0 if py < cy else -18.0
    return max(0, min(255, int(value)))


def _background_shade(px: float, py: float, cx: float, cy: float, hw: float, hh: float, d: float) -> int:
    t = (py - (cy - hh)) / (2 * hh) if hh else 0.5
    value = 26.0 - 18.0 * t
    if d > -2.0:
        value -= 4.0
    return max(0, min(255, int(value)))


def _shadow_shade(px: float, py: float, cx: float, cy: float, hw: float, hh: float, d: float) -> int:
    return 3


def _dumbbell_shade(px: float, py: float, cx: float, cy: float, hw: float, hh: float, d: float) -> int:
    t = (py - (cy - hh)) / (2 * hh) if hh else 0.5
    u = (px - (cx - hw)) / (2 * hw) if hw else 0.5
    value = 238.0 - 95.0 * t
    value -= 22.0 * max(0.0, u - 0.55) * 2.0
    value += 14.0 * max(0.0, 0.30 - u) * 2.0
    if t < 0.22:
        value += 22.0 * (1.0 - t / 0.22)
    if t > 0.80:
        value -= 30.0 * ((t - 0.80) / 0.20)
    if d > -2.5:
        value += 16.0 if py < cy else -24.0
    return max(0, min(255, int(value)))


def _paint(
    shape: tuple[float, float, float, float, float],
    size: int,
    ss: int,
    alpha: bytearray,
    gray: bytearray,
    set_alpha: bool,
    shade: Shade,
) -> None:
    scale = size / _BASE_SIZE
    cx, cy, hw, hh, r = (component * scale for component in shape)
    width = size * ss
    x0 = max(0, int((cx - hw) * ss) - 2)
    x1 = min(width, int((cx + hw) * ss) + 3)
    y0 = max(0, int((cy - hh) * ss) - 2)
    y1 = min(width, int((cy + hh) * ss) + 3)
    for y in range(y0, y1):
        py = (y + 0.5) / ss
        row = y * width
        for x in range(x0, x1):
            px = (x + 0.5) / ss
            distance = _sdf_round_rect(px, py, cx, cy, hw, hh, r)
            if distance <= 0.0:
                index = row + x
                if set_alpha:
                    alpha[index] = 255
                gray[index] = shade(px, py, cx, cy, hw, hh, distance)


def render_rgba(size: int = 256, ss: int = 4) -> bytes:
    width = size * ss
    alpha = bytearray(width * width)
    gray = bytearray(width * width)
    _paint(_OUTER_SQUARE, size, ss, alpha, gray, True, _outer_shade)
    _paint(_INNER_SQUARE, size, ss, alpha, gray, False, _background_shade)
    for shape in _DUMBBELL_SHADOW:
        _paint(shape, size, ss, alpha, gray, False, _shadow_shade)
    for shape in _DUMBBELL:
        _paint(shape, size, ss, alpha, gray, False, _dumbbell_shade)

    total = ss * ss
    output = bytearray(size * size * 4)
    for y in range(size):
        for x in range(size):
            alpha_sum = 0
            gray_sum = 0
            covered = 0
            for dy in range(ss):
                base = (y * ss + dy) * width + x * ss
                for dx in range(ss):
                    index = base + dx
                    coverage = alpha[index]
                    if coverage:
                        alpha_sum += coverage
                        gray_sum += gray[index]
                        covered += 1
            if covered:
                color = gray_sum // covered
                offset = (y * size + x) * 4
                output[offset] = color
                output[offset + 1] = color
                output[offset + 2] = color
                output[offset + 3] = alpha_sum // total
    return bytes(output)


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def png_bytes(rgba: bytes, size: int) -> bytes:
    stride = size * 4
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        raw.extend(rgba[y * stride : (y + 1) * stride])
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + _png_chunk(b"IEND", b"")
    )


def ico_bytes(images: list[tuple[int, bytes]]) -> bytes:
    count = len(images)
    header = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries = bytearray()
    payload = bytearray()
    for size, png in images:
        dimension = 0 if size >= 256 else size
        entries.extend(
            struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(png), offset)
        )
        offset += len(png)
        payload.extend(png)
    return header + bytes(entries) + bytes(payload)


def asset_path(name: str) -> Path:
    return Path(__file__).resolve().parent / "assets" / name


def write_assets(directory: str | Path | None = None) -> Path:
    assets = Path(directory) if directory is not None else Path(__file__).resolve().parent / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    png = png_bytes(render_rgba(256, ss=4), 256)
    (assets / "icon.png").write_bytes(png)
    sizes = (16, 32, 48, 64, 128, 256)
    images = [(size, png_bytes(render_rgba(size, ss=4), size)) for size in sizes]
    (assets / "icon.ico").write_bytes(ico_bytes(images))
    return assets
