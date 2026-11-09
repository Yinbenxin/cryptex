"""
Loading PSI input sets from memory or files, and writing results.

Files are always read as a stream; `load_items` materializes the whole set.
Bucketed runs spill the input to per-bucket files in the core library
instead (see `_store`).
"""

import csv
import os

# utf-8-sig transparently strips a BOM (common in Excel exports).
DEFAULT_ENCODING = "utf-8-sig"


def to_bytes(item):
    """Encode one item: str as UTF-8, bytes-like as is"""
    if isinstance(item, str):
        return item.encode("utf-8")
    if isinstance(item, (bytes, bytearray, memoryview)):
        return bytes(item)
    raise TypeError(f"PSI items must be str or bytes, got {type(item).__name__}")


def dedupe(items):
    """Drop duplicates (compared by encoded bytes), keeping first occurrence"""
    seen = set()
    out = []
    for item in items:
        key = to_bytes(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def is_path(data):
    return isinstance(data, (str, os.PathLike))


def _iter_lines(path, encoding):
    with open(path, encoding=encoding, newline="") as f:
        for line in f:
            line = line.strip()
            if line:
                yield line


def _iter_csv_column(path, column, has_header, delimiter, encoding):
    with open(path, encoding=encoding, newline="") as f:
        reader = csv.reader(f, delimiter=delimiter)
        if isinstance(column, str):
            if not has_header:
                raise ValueError("column given by name requires has_header=True")
            header = next(reader, None)
            if header is None:
                return
            names = [h.strip() for h in header]
            if column not in names:
                raise ValueError(f"column {column!r} not found in header {names}")
            index = names.index(column)
        else:
            index = int(column)
            if has_header:
                next(reader, None)

        for row in reader:
            if not row:
                continue
            if index >= len(row):
                raise ValueError(
                    f"{path}: line {reader.line_num} has no column {column!r}"
                )
            value = row[index].strip()
            if value:
                yield value


def iter_file_items(path, column=None, has_header=True, delimiter=",",
                    encoding=DEFAULT_ENCODING):
    """Stream the values of a file (no dedupe): one per line, or a CSV column

    Surrounding whitespace is stripped and empty values are skipped.
    """
    if column is None:
        return _iter_lines(path, encoding)
    return _iter_csv_column(path, column, has_header, delimiter, encoding)


def load_items(data, column=None, has_header=True, delimiter=",",
               encoding=DEFAULT_ENCODING):
    """Load a PSI input set

    Args:
        data: An iterable of str/bytes items, or a path to a file.
            - Without `column`: text file, one item per line.
            - With `column`: CSV file, items taken from that column.
            Surrounding whitespace is stripped and empty values are skipped.
        column: CSV column, by header name (str) or 0-based index (int)
        has_header: Whether the CSV has a header row
        delimiter: CSV delimiter
        encoding: File encoding

    Returns:
        List of items with duplicates removed (first occurrence kept).
        Items read from files are str.
    """
    if is_path(data):
        items = list(iter_file_items(data, column, has_header, delimiter, encoding))
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("pass a list of items or a file path, not a single bytes value")
    else:
        if column is not None:
            raise ValueError("column only applies to file input")
        items = list(data)
    return dedupe(items)


def write_items(path, items, encoding="utf-8"):
    """Write items to a text file, one per line"""
    with open(path, "w", encoding=encoding, newline="\n") as f:
        for item in items:
            if isinstance(item, (bytes, bytearray, memoryview)):
                item = bytes(item).decode(encoding)
            f.write(f"{item}\n")


# ---- estimating the size of a file without reading all of it ----

_SAMPLE_BYTES = 4 << 20


def estimate_items(path, has_header=True, column=None):
    """Approximate number of values in a file, from its first few MiB

    Counts lines; exact for files up to 4 MiB without blank lines. Only used
    to size buckets, where an estimate is enough.
    """
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        sample = f.read(_SAMPLE_BYTES)
    if not sample:
        return 0
    lines = sample.count(b"\n") + (0 if sample.endswith(b"\n") else 1)
    if size > len(sample):
        lines = int(lines * size / len(sample))
    if column is not None and has_header:
        lines -= 1
    return max(lines, 0)


def select_positions(values, marked, expected_total):
    """Yield the values whose position has its bit set in `marked`

    `values` must replay the same input that was partitioned; a different
    length means the file changed during the run.
    """
    total = 0
    for pos, value in enumerate(values):
        if marked[pos >> 3] & (1 << (pos & 7)):
            yield value
        total = pos + 1
    if total != expected_total:
        raise RuntimeError(
            f"input changed during PSI: read {total} values, expected {expected_total}")
