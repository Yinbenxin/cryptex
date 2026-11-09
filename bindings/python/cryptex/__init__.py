"""
Cryptex Python bindings

Python wrapper for the cryptex cryptographic library.
"""

import logging as _logging

from .version import __version__
from ._ffi import CryptexError
from .channel import CallbackChannel, Channel, ChannelClosed, MemoryChannel, TcpChannel
from .cryptex import Cryptex
from .vole import JobRole, VoleJob
from . import pir
from .pir import Padding, PirClient, PirDatabase, PirParams, PirServer
from .psi import (
    DEFAULT_BUCKET_SIZE, MAX_BUCKETS, MAX_THREADS, BucketHash, Curve, Pool, Protocol, Psi, PsiParty, Role,
    bucket_of,
)

__all__ = [
    'BucketHash',
    'CallbackChannel',
    'Channel',
    'ChannelClosed',
    'Cryptex',
    'CryptexError',
    'Curve',
    'JobRole',
    'DEFAULT_BUCKET_SIZE',
    'MAX_BUCKETS',
    'MAX_THREADS',
    'MemoryChannel',
    'Padding',
    'PirClient',
    'PirDatabase',
    'PirParams',
    'PirServer',
    'Pool',
    'Protocol',
    'Psi',
    'PsiParty',
    'Role',
    'TcpChannel',
    'VoleJob',
    '__version__',
    'bucket_of',
    'pir',
]

# Library convention: stay silent unless the application configures logging.
_logging.getLogger(__name__).addHandler(_logging.NullHandler())
