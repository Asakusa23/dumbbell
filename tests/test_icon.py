import struct
import unittest

from dumbbell.icon import ASCII_LOGO, ico_bytes, png_bytes, render_rgba


class IconTests(unittest.TestCase):
    def test_ascii_logo_shape(self):
        lines = ASCII_LOGO.splitlines()
        self.assertEqual(len(lines), 7)
        self.assertTrue(any("=" in line for line in lines))
        self.assertTrue(any("#" in line for line in lines))
        self.assertTrue(any("\\" in line for line in lines))
        self.assertTrue(all(line.strip() for line in lines))
        self.assertTrue(all(len(line) == len(lines[0]) for line in lines))

    def test_render_rgba_dimensions(self):
        size = 32
        rgba = render_rgba(size, ss=2)
        self.assertEqual(len(rgba), size * size * 4)
        self.assertTrue(any(rgba[index] for index in range(3, len(rgba), 4)))

    def test_render_has_3d_shading(self):
        rgba = render_rgba(64, ss=2)
        grays = {rgba[index] for index in range(0, len(rgba), 4) if rgba[index + 3]}
        self.assertGreater(len(grays), 8)
        self.assertGreater(max(grays), 200)
        self.assertLess(min(grays), 40)

    def test_png_signature_and_header(self):
        size = 16
        data = png_bytes(render_rgba(size, ss=2), size)
        self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
        width, height = struct.unpack(">II", data[16:24])
        self.assertEqual((width, height), (size, size))
        self.assertTrue(data.endswith(b"IEND\xaeB`\x82"))

    def test_ico_contains_all_images(self):
        images = [(16, b"a"), (32, b"bb")]
        data = ico_bytes(images)
        reserved, image_type, count = struct.unpack("<HHH", data[:6])
        self.assertEqual((reserved, image_type, count), (0, 1, 2))
        first_width, first_height = data[6], data[7]
        self.assertEqual((first_width, first_height), (16, 16))
        self.assertIn(b"bb", data)


if __name__ == "__main__":
    unittest.main()
