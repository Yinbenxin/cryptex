"""
Build hooks for the cryptex wheel.

The package loads the core library with ctypes, so the wheel must carry
libcryptex for its platform: build_py runs `cargo build --release` in
../../core (or takes the file named by $CRYPTEX_LIB) and copies the library
into cryptex/lib/, where cryptex._ffi looks first. The wheel is tagged
py3-none-<platform>: any Python 3, no extension modules, one platform.

Version: cryptex/version.py, overridden by $CRYPTEX_VERSION (CI uses it for
dev builds such as 0.1.0.dev123).

Cross builds (CI): $CRYPTEX_LIB points at a library built for another
target, and the wheel is tagged with `bdist_wheel --plat-name`, e.g.
manylinux2014_aarch64; the library name is then taken from the plat name.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.build_py import build_py

try:
    from setuptools.command.bdist_wheel import bdist_wheel
except ImportError:  # setuptools < 70.1
    from wheel.bdist_wheel import bdist_wheel

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / "core"


def _version():
    env = os.environ.get("CRYPTEX_VERSION")
    if env:
        return env
    text = (HERE / "cryptex" / "version.py").read_text(encoding="utf-8")
    return re.search(r'__version__\s*=\s*"([^"]+)"', text).group(1)


def _lib_name(plat=None):
    plat = plat or sys.platform
    if plat.startswith("win"):
        return "cryptex.dll"
    if plat.startswith(("darwin", "macosx")):
        return "libcryptex.dylib"
    return "libcryptex.so"


def _native_lib():
    """Path of the core library to bundle, building it if needed"""
    env = os.environ.get("CRYPTEX_LIB")
    if env:
        return Path(env)
    if not CORE.is_dir():
        raise RuntimeError(f"{CORE} not found: build from a source checkout or set CRYPTEX_LIB")
    cmd = ["cargo", "build", "--release", "--lib"]
    if (CORE / "Cargo.lock").exists():
        cmd.append("--locked")
    subprocess.check_call(cmd, cwd=CORE)
    return CORE / "target" / "release" / _lib_name()


class BuildPy(build_py):
    def run(self):
        super().run()
        lib = _native_lib()
        if not lib.is_file():
            raise RuntimeError(f"core library {lib} not found")
        plat = self.distribution.get_command_obj("bdist_wheel").plat_name
        pkg = Path(self.build_lib) / "cryptex"
        (pkg / "lib").mkdir(parents=True, exist_ok=True)
        shutil.copy2(lib, pkg / "lib" / _lib_name(plat))
        # The installed package reports the version it was built as.
        (pkg / "version.py").write_text(f'__version__ = "{_version()}"\n', encoding="utf-8")


class BinaryDistribution(Distribution):
    """Platform-specific: install into platlib, tag with the platform"""

    def has_ext_modules(self):
        return True


class BdistWheel(bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False  # carries a native library

    def get_tag(self):
        _, _, plat = super().get_tag()
        return "py3", "none", plat


setup(
    version=_version(),
    distclass=BinaryDistribution,
    cmdclass={"build_py": BuildPy, "bdist_wheel": BdistWheel},
)
