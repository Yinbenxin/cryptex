"""
Input loading tests: lists, text files, CSV columns, dedupe and output.
"""

import os
import tempfile
import unittest
from pathlib import Path

from cryptex import _data


class LoadItemsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name, content, encoding="utf-8"):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w", encoding=encoding, newline="") as f:
            f.write(content)
        return p

    def test_list_is_deduped_keeping_first(self):
        self.assertEqual(_data.load_items(["b", "a", "b"]), ["b", "a"])

    def test_str_and_bytes_with_same_encoding_are_duplicates(self):
        self.assertEqual(_data.load_items(["中", "中".encode("utf-8")]), ["中"])

    def test_generator_input(self):
        self.assertEqual(_data.load_items(x for x in ["a", "b"]), ["a", "b"])

    def test_rejects_non_str_items(self):
        with self.assertRaises(TypeError):
            _data.load_items([1, 2])

    def test_rejects_single_bytes_value(self):
        with self.assertRaises(TypeError):
            _data.load_items(b"abc")

    def test_column_requires_file(self):
        with self.assertRaises(ValueError):
            _data.load_items(["a"], column="id")

    def test_text_file_strips_and_skips_blank_lines(self):
        p = self.path("a.txt", "  a\r\nb  \n\n   \nc")
        self.assertEqual(_data.load_items(p), ["a", "b", "c"])

    def test_text_file_accepts_pathlike_and_bom(self):
        p = self.path("bom.txt", "﻿a\nb\n")
        self.assertEqual(_data.load_items(Path(p)), ["a", "b"])

    def test_text_file_custom_encoding(self):
        p = self.path("gbk.txt", "张三\n李四\n", encoding="gbk")
        self.assertEqual(_data.load_items(p, encoding="gbk"), ["张三", "李四"])

    def test_csv_by_name(self):
        p = self.path("a.csv", "name, id \nx,1\ny,2\nz,1\n")
        self.assertEqual(_data.load_items(p, column="id"), ["1", "2"])

    def test_csv_by_index_with_and_without_header(self):
        p = self.path("a.csv", "id,name\n1,x\n2,y\n")
        self.assertEqual(_data.load_items(p, column=0), ["1", "2"])
        self.assertEqual(_data.load_items(p, column=0, has_header=False), ["id", "1", "2"])

    def test_csv_quoted_and_custom_delimiter(self):
        p = self.path("a.tsv", 'id\tnote\n"a\tb"\tx\nc\ty\n')
        self.assertEqual(_data.load_items(p, column="id", delimiter="\t"), ["a\tb", "c"])

    def test_csv_skips_empty_cells_and_rows(self):
        p = self.path("a.csv", "id\n1\n\n,\n2\n")
        self.assertEqual(_data.load_items(p, column=0), ["1", "2"])

    def test_csv_missing_column(self):
        p = self.path("a.csv", "id\n1\n")
        with self.assertRaisesRegex(ValueError, "not found"):
            _data.load_items(p, column="phone")

    def test_csv_short_row_reports_line(self):
        p = self.path("a.csv", "id,phone\n1,2\n3\n")
        with self.assertRaisesRegex(ValueError, "line 3"):
            _data.load_items(p, column="phone")

    def test_csv_name_requires_header(self):
        p = self.path("a.csv", "1\n")
        with self.assertRaises(ValueError):
            _data.load_items(p, column="id", has_header=False)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            _data.load_items(os.path.join(self.tmp.name, "nope.txt"))


class WriteItemsTest(unittest.TestCase):
    def test_writes_str_and_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.txt")
            _data.write_items(p, ["a", "中".encode("utf-8")])
            with open(p, encoding="utf-8") as f:
                self.assertEqual(f.read(), "a\n中\n")


if __name__ == "__main__":
    unittest.main()
