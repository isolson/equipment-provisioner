"""Device handlers for various network equipment manufacturers.

This package intentionally does NOT import the per-vendor handler
modules: the VendorSpec registry (``provisioner.vendor_registry``)
imports each vendor's handler class directly and derives
``HandlerManager.HANDLER_MAP`` from the specs (Story 6 / #76).
Enumerating vendors here as well was an ImportError-on-removal S1 site —
deleting a vendor's module plus its spec entry must not be able to crash
the service at boot. Import vendor handler classes from their own
modules (``provisioner.handlers.mikrotik`` etc.) or resolve them through
the registry / ``HandlerManager.handler_class_for``.

``MockHandler`` (simulation-only, ``provision --mock``) stays outside
the vendor registry by design and is exported here.
"""

from .base import BaseHandler, DeviceInfo
from .mock import MockHandler

__all__ = [
    "BaseHandler",
    "DeviceInfo",
    "MockHandler",
]
