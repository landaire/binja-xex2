"""Exercise loader initialization with both BinaryView handle APIs, without a BN license."""
import ast
from pathlib import Path
import unittest


class ReadFailed(Exception):
    pass


class UnreadableData:
    length = 4

    def read(self, offset, length):
        raise ReadFailed('input read failed')


def loader_class(base):
    source = Path(__file__).resolve().parents[1] / 'xbox360_xex2_loader.py'
    tree = ast.parse(source.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Xbox360Xex2View')
    namespace = {'BinaryView': base}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace[node.name]


class ViewCompatibilityTests(unittest.TestCase):
    def test_read_failure_preserved_with_read_only_handle(self):
        class ModernView:
            @property
            def handle(self):
                return self._handle

        cls = loader_class(ModernView)
        view = cls.__new__(cls)
        with self.assertRaises(ReadFailed):
            cls.__init__(view, UnreadableData())
        self.assertIsNone(view.handle)

    def test_read_failure_preserved_with_legacy_handle(self):
        class LegacyView:
            pass

        cls = loader_class(LegacyView)
        view = cls.__new__(cls)
        with self.assertRaises(ReadFailed):
            cls.__init__(view, UnreadableData())
        self.assertIsNone(view.handle)


if __name__ == '__main__':
    unittest.main()
