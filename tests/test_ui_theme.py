import unittest

from cleaner.ui.theme import format_size


class FormatSizeTests(unittest.TestCase):
    def test_bytes_keep_integer_format(self) -> None:
        self.assertEqual("0 B", format_size(0))
        self.assertEqual("512 B", format_size(512))
        self.assertEqual("1,023 B", format_size(1023))

    def test_larger_units_use_one_decimal(self) -> None:
        self.assertEqual("1.0 KB", format_size(1024))
        self.assertEqual("1.5 MB", format_size(1024 * 1024 * 3 // 2))
        self.assertEqual("2.0 GB", format_size(2 * 1024**3))
        self.assertEqual("3.0 TB", format_size(3 * 1024**4))


if __name__ == "__main__":
    unittest.main()
