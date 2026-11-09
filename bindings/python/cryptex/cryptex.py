"""
Core cryptex wrapper using ctypes
"""

import ctypes

from . import _ffi


class Cryptex:
    """Main interface to the cryptex library"""

    def __init__(self, lib_path=None):
        """
        Initialize the cryptex library

        Args:
            lib_path: Optional path to the shared library
        """
        self._lib = _ffi.lib(lib_path)

    def version(self):
        """Get library version"""
        version_ptr = self._lib.cryptex_version()
        try:
            return ctypes.string_at(version_ptr).decode("utf-8")
        finally:
            self._lib.cryptex_free_string(version_ptr)
