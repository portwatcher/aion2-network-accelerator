#!/usr/bin/env python3
"""Generate app icons at required sizes for Tauri bundling."""
import struct, zlib, os, sys

def make_png(size):
    pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            border = max(1, size // 16)
            if x < border or x >= size - border or y < border or y >= size - border:
                row.extend([233, 69, 96, 255])
            elif abs(x - size // 2) <= (size - y) * size // (2 * size) and y > size // 8:
                row.extend([233, 69, 96, 255])
            else:
                row.extend([26, 26, 46, 255])
        pixels.append(bytes([0]) + bytes(row))

    raw = b"".join(pixels)
    compressed = zlib.compress(raw)

    def chunk(ctype, data):
        c = ctype + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", compressed)
    png += chunk(b"IEND", b"")
    return png


def make_ico(sizes):
    """Create a .ico file from multiple PNG sizes."""
    images = []
    for s in sizes:
        images.append(make_png(s))

    # ICO header: reserved(2) + type(2) + count(2)
    header = struct.pack("<HHH", 0, 1, len(images))
    entries = b""
    data = b""
    offset = 6 + 16 * len(images)  # header + entries

    for i, (s, img) in enumerate(zip(sizes, images)):
        w = s if s < 256 else 0
        h = s if s < 256 else 0
        entries += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
        data += img

    return header + entries + data


def make_icns(png_data):
    """Create a minimal .icns with a 256x256 PNG (ic08)."""
    icon_type = b"ic08"
    entry = icon_type + struct.pack(">I", len(png_data) + 8) + png_data
    total = 8 + len(entry)
    return b"icns" + struct.pack(">I", total) + entry


outdir = os.path.join(os.path.dirname(__file__), "..", "crates", "aion2-app", "icons")
os.makedirs(outdir, exist_ok=True)

for size, name in [(32, "32x32.png"), (128, "128x128.png"), (256, "128x128@2x.png"), (512, "icon.png")]:
    path = os.path.join(outdir, name)
    with open(path, "wb") as f:
        f.write(make_png(size))
    print(f"Generated {name} ({size}x{size})")

# Generate .ico (16, 32, 48, 256)
ico_path = os.path.join(outdir, "icon.ico")
with open(ico_path, "wb") as f:
    f.write(make_ico([16, 32, 48, 256]))
print("Generated icon.ico")

# Generate .icns (256x256)
icns_path = os.path.join(outdir, "icon.icns")
with open(icns_path, "wb") as f:
    f.write(make_icns(make_png(256)))
print("Generated icon.icns")
