import os
import unittest

from cleaner.safety import windows_explorer_path


class WindowsPathSafetyTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows 路径接口测试")
    def test_explorer_path_is_absolute_and_points_to_the_system_binary(self) -> None:
        explorer = windows_explorer_path()

        self.assertTrue(explorer.is_absolute())
        self.assertEqual("explorer.exe", explorer.name.casefold())
        self.assertTrue(explorer.is_file())


if __name__ == "__main__":
    unittest.main()
