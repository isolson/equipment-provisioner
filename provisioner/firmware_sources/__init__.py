"""Vendor-specific firmware source implementations.

This package intentionally does NOT import the per-vendor source modules:
the VendorSpec registry (``provisioner.vendor_registry``) imports each
vendor's source class directly and derives ``FirmwareChecker.SOURCE_MAP``
from the specs (Story 6 / #76). Enumerating vendors here as well was the
last ImportError-on-removal S1 site — deleting a vendor's module plus its
spec entry must not be able to crash the service at boot.
"""

from .base import BaseFirmwareSource, RemoteFirmwareInfo

__all__ = [
    "BaseFirmwareSource",
    "RemoteFirmwareInfo",
]
