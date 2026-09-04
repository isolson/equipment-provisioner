"""Vendor-neutral field ownership contract.

Every configuration field has exactly one owner:

``fleet_policy``
    Written by the standard baseline and verified as an exact value.
``role``
    Written by the standard baseline and verified as an exact value. These
    fields define the radio role (for example SM).
``secret``
    Written only by the handler's secret path. Never in a template. Never
    logged. Verified by presence only.
``device_default``
    Never written by the provisioner. A field that no contract classifies is a
    device default. Optionally verified unchanged against the no-config fixture.
``mode_action``
    Never in the standard baseline. Written only by the explicit post-provision
    mode workflow (AP or PTP).

This module must contain no vendor names, perform no I/O, and never log a
field value. Handlers declare one :class:`OwnershipContract` each. Shared code
uses the contract to lint templates and to derive verification expectations.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Pattern,
    Tuple,
    Union,
)


class Owner(str, Enum):
    """The single owner group of a configuration field."""

    FLEET_POLICY = "fleet_policy"
    ROLE = "role"
    SECRET = "secret"
    DEVICE_DEFAULT = "device_default"
    MODE_ACTION = "mode_action"


#: Structural path. A string component is a mapping key. An int component is a
#: list index.
FieldPath = Tuple[Union[str, int], ...]

#: Roles whose template may contain ``mode_action`` fields.
MODE_ROLES = frozenset(("AP", "PTP"))

#: Key shapes that always mean a secret, regardless of vendor.
DEFAULT_SECRET_RE = re.compile(
    r"(?:password|passphrase|psk|secret|token|community|private[_-]?key|encryption[_-]?key)",
    re.IGNORECASE,
)

_PATH_TOKEN_RE = re.compile(r"([^.\[\]]+)|\[(\d*)\]")
#: Wildcard list index in a contract path (``profiles[].ssid``).
ANY_INDEX = "[]"


def parse_path(dotted: str) -> FieldPath:
    """Parse ``a.b[0].c`` into ``("a", "b", 0, "c")``."""
    if not isinstance(dotted, str) or not dotted:
        raise ValueError("field path must be a non-empty string")
    path = []  # type: List[Union[str, int]]
    position = 0
    for match in _PATH_TOKEN_RE.finditer(dotted):
        if match.start() != position and dotted[position:match.start()] != ".":
            raise ValueError("invalid field path: %s" % dotted)
        key, index = match.group(1), match.group(2)
        if key is not None:
            path.append(key)
        elif index == "":
            path.append(ANY_INDEX)
        else:
            path.append(int(index))
        position = match.end()
    if position != len(dotted):
        raise ValueError("invalid field path: %s" % dotted)
    return tuple(path)


def format_path(path: FieldPath) -> str:
    """Render a structural path as ``a.b[0].c``."""
    parts = []  # type: List[str]
    for component in path:
        if isinstance(component, int):
            parts.append("[%d]" % component)
        elif component == ANY_INDEX:
            parts.append("[]")
        else:
            parts.append(("." if parts else "") + component)
    return "".join(parts)


def flatten(config: Any, prefix: FieldPath = ()) -> Iterator[Tuple[FieldPath, Any]]:
    """Yield ``(path, scalar)`` pairs for every leaf in *config*.

    Keys that start with ``_`` are template metadata and are skipped.
    """
    if isinstance(config, dict):
        for key, value in config.items():
            if isinstance(key, str) and key.startswith("_"):
                continue
            for item in flatten(value, prefix + (key,)):
                yield item
    elif isinstance(config, list):
        for index, value in enumerate(config):
            for item in flatten(value, prefix + (index,)):
                yield item
    else:
        yield prefix, config


def get_path(config: Any, path: FieldPath) -> Tuple[bool, Any]:
    """Return ``(found, value)`` for *path* inside *config*."""
    node = config
    for component in path:
        if isinstance(component, int):
            if not isinstance(node, list) or component >= len(node):
                return False, None
            node = node[component]
        else:
            if not isinstance(node, dict) or component not in node:
                return False, None
            node = node[component]
    return True, node


@dataclass(frozen=True)
class Violation:
    """A template field that breaks the contract. Carries no value."""

    path: str
    reason: str


@dataclass(frozen=True)
class OwnershipContract:
    """One handler's field ownership table."""

    #: Explicit classifications by structural path (relative to ``root``).
    fields: Mapping[FieldPath, Owner] = field(default_factory=dict)
    #: Required role fields: ``family_dir -> ROLE -> paths``.
    role_fields: Mapping[str, Mapping[str, FrozenSet[FieldPath]]] = field(
        default_factory=dict
    )
    #: Other fields a baseline must carry as one coherent set (any owner),
    #: for example a management VLAN that needs a zone, a port flag, and a
    #: VAP flag together: ``family_dir -> ROLE -> paths``.
    required_fields: Mapping[str, Mapping[str, FrozenSet[FieldPath]]] = field(
        default_factory=dict
    )
    #: Key shapes that are secrets even when not listed in ``fields``.
    secret_re: Pattern = DEFAULT_SECRET_RE
    #: Container path where the device fields live inside a template document,
    #: for example ``("device_props",)``. Keys outside the root are metadata.
    root: FieldPath = ()
    #: ``fields`` with every list index (concrete or wildcard) folded to the
    #: wildcard, so ``vaps[0].profiles[]`` and ``vaps[].profiles[3]`` match.
    generic_fields: Mapping[FieldPath, Owner] = field(default_factory=dict)

    def __post_init__(self) -> None:
        generic = {}  # type: Dict[FieldPath, Owner]
        for path, owner in self.fields.items():
            generic.setdefault(_generic(path), owner)
        object.__setattr__(self, "generic_fields", generic)

    @classmethod
    def from_dotted(
        cls,
        fields: Mapping[str, Owner],
        role_fields: Optional[Mapping[str, Mapping[str, Tuple[str, ...]]]] = None,
        secret_re: Pattern = DEFAULT_SECRET_RE,
        root: str = "",
        required_fields: Optional[Mapping[str, Mapping[str, Tuple[str, ...]]]] = None,
    ) -> "OwnershipContract":
        """Build a contract from dotted path strings."""
        parsed_fields = {parse_path(path): Owner(owner) for path, owner in fields.items()}

        def _parse(table):
            parsed = {}  # type: Dict[str, Dict[str, FrozenSet[FieldPath]]]
            for family_dir, roles in (table or {}).items():
                parsed[family_dir] = {
                    role.upper(): frozenset(parse_path(path) for path in paths)
                    for role, paths in roles.items()
                }
            return parsed

        return cls(
            fields=parsed_fields,
            role_fields=_parse(role_fields),
            secret_re=secret_re,
            root=parse_path(root) if root else (),
            required_fields=_parse(required_fields),
        )

    def owners(self, owner: Owner) -> FrozenSet[FieldPath]:
        """Return every explicitly classified path with *owner*."""
        return frozenset(path for path, value in self.fields.items() if value is owner)

    def required_role_fields(self, family_dir: Optional[str], role: str) -> FrozenSet[FieldPath]:
        """Return the role fields a template for *family_dir* and *role* must set."""
        if not family_dir:
            return frozenset()
        return self.role_fields.get(family_dir, {}).get(role.upper(), frozenset())

    def required_baseline_fields(self, family_dir: Optional[str], role: str) -> FrozenSet[FieldPath]:
        """Return the coherent-set fields a template must carry (any owner)."""
        if not family_dir:
            return frozenset()
        return self.required_fields.get(family_dir, {}).get(role.upper(), frozenset())

    def device_fields(self, config: Any) -> Any:
        """Return the part of *config* under ``root``.

        A document that already lacks the root container is treated as
        already unwrapped, so handlers can pass either shape.
        """
        if not self.root:
            return config
        found, node = get_path(config, self.root)
        return node if found else config


def _generic(path: FieldPath) -> FieldPath:
    """Fold every list index to the wildcard."""
    return tuple(ANY_INDEX if isinstance(c, int) or c == ANY_INDEX else c for c in path)


def _explicit_owner(contract: OwnershipContract, path: FieldPath) -> Optional[Owner]:
    """Return the table entry for *path* or its longest classified prefix.

    A table entry for a container (for example a list of preferred access
    points) covers every field inside that container.
    """
    generic = _generic(path)
    for length in range(len(path), 0, -1):
        owner = contract.fields.get(path[:length])
        if owner is None:
            owner = contract.generic_fields.get(generic[:length])
        if owner is not None:
            return owner
    return None


def classify(contract: OwnershipContract, path: FieldPath) -> Owner:
    """Return the owner of *path*. Unclassified fields are device defaults."""
    owner = _explicit_owner(contract, path)
    if owner is not None:
        return owner
    for component in path:
        if isinstance(component, str) and contract.secret_re.search(component):
            return Owner.SECRET
    return Owner.DEVICE_DEFAULT


def is_classified(contract: OwnershipContract, path: FieldPath) -> bool:
    """Return whether *path* has a table entry (or prefix) or a secret-shaped key."""
    if _explicit_owner(contract, path) is not None:
        return True
    return any(
        isinstance(component, str) and contract.secret_re.search(component)
        for component in path
    )


def template_violations(
    contract: OwnershipContract,
    config: Any,
    role: str,
    family_dir: Optional[str] = None,
    strict: bool = True,
) -> List[Violation]:
    """Check a template against the contract. Returns field names only.

    A baseline (role ``SM``) may contain only ``fleet_policy`` and ``role``
    fields. A mode template (``AP`` or ``PTP``) may also contain
    ``mode_action`` fields. Secrets and device defaults are never allowed.
    Unclassified fields are violations when *strict* is true. A required role
    field that is missing is a violation.
    """
    allowed = {Owner.FLEET_POLICY, Owner.ROLE}
    if role.upper() in MODE_ROLES:
        allowed.add(Owner.MODE_ACTION)
    violations = []  # type: List[Violation]
    device_fields = contract.device_fields(config)
    present = set()  # type: set
    for path, _value in flatten(device_fields):
        present.add(path)
        owner = classify(contract, path)
        display = format_path(path)
        if owner in allowed:
            continue
        if owner is Owner.DEVICE_DEFAULT and not is_classified(contract, path):
            if strict:
                violations.append(Violation(display, "unclassified"))
            continue
        violations.append(Violation(display, owner.value))
    prefixes = set()  # type: set
    for p in present:
        for length in range(1, len(p) + 1):
            prefixes.add(p[:length])
            prefixes.add(_generic(p[:length]))
    for path in sorted(contract.required_role_fields(family_dir, role), key=format_path):
        if path not in prefixes and _generic(path) not in prefixes:
            violations.append(Violation(format_path(path), "missing_role_field"))
    for path in sorted(contract.required_baseline_fields(family_dir, role), key=format_path):
        if path not in prefixes and _generic(path) not in prefixes:
            violations.append(Violation(format_path(path), "missing_required_field"))
    return violations


def expected_values(
    contract: OwnershipContract,
    applied: Any,
    include_mode_action: bool = False,
) -> Dict[str, Any]:
    """Return the read-back expectation set for an applied configuration.

    Only ``fleet_policy`` and ``role`` fields (and ``mode_action`` fields when
    the mode workflow asks for them) are verified as exact values. Secrets and
    device defaults are never part of the expectation set.
    """
    wanted = {Owner.FLEET_POLICY, Owner.ROLE}
    if include_mode_action:
        wanted.add(Owner.MODE_ACTION)
    expectations = {}  # type: Dict[str, Any]
    for path, value in flatten(contract.device_fields(applied)):
        if classify(contract, path) in wanted:
            expectations[format_path(path)] = value
    return expectations


def unchanged_expectations(
    contract: OwnershipContract,
    fixture_values: Mapping[str, Any],
) -> Dict[str, Any]:
    """Return device-default fields whose read-back must equal the fixture."""
    expectations = {}  # type: Dict[str, Any]
    for dotted, value in fixture_values.items():
        if classify(contract, parse_path(dotted)) is Owner.DEVICE_DEFAULT:
            expectations[dotted] = value
    return expectations


def reduce_to_baseline(contract: OwnershipContract, config: Any, role: str) -> Any:
    """Return *config* with only the leaves the role may own, structure kept.

    An SM baseline keeps ``fleet_policy`` and ``role`` leaves. AP and PTP
    keep ``mode_action`` leaves too. Secrets, device defaults, identity, and
    unclassified leaves are dropped. Lists keep their surviving items in
    order; an item that loses every leaf is dropped.
    """
    allowed = {Owner.FLEET_POLICY, Owner.ROLE}
    if role.upper() in MODE_ROLES:
        allowed.add(Owner.MODE_ACTION)

    def keep(node: Any, path: FieldPath) -> Any:
        if isinstance(node, dict):
            out = {}
            for key, value in node.items():
                if isinstance(key, str) and key.startswith("_"):
                    continue
                child = keep(value, path + (key,))
                if child is not None:
                    out[key] = child
            return out or None
        if isinstance(node, list):
            items = [keep(value, path + (index,)) for index, value in enumerate(node)]
            items = [item for item in items if item is not None]
            return items or None
        return node if classify(contract, path) in allowed else None

    device_fields = contract.device_fields(config)
    reduced = keep(device_fields, ()) or {}
    if contract.root:
        found, _ = get_path(config, contract.root)
        if found:
            wrapper = {}  # type: Dict[str, Any]
            node = wrapper
            for component in contract.root[:-1]:
                node[component] = {}
                node = node[component]
            node[contract.root[-1]] = reduced
            return wrapper
    return reduced
