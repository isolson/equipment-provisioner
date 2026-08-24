"""Tests for the shared config deep-merge utility (config_merge.py).

The algorithm is the one the tree already trusted (promoted from the
Tachyon handler): dicts merge recursively with the overlay winning per
key; lists, scalars, and None replace wholesale.
"""

import copy

from provisioner.config_merge import deep_merge


def test_dicts_merge_recursively_overlay_wins():
    base = {"a": {"b": 1, "keep": "x"}, "top": "base"}
    overlay = {"a": {"b": 2}, "top": "overlay"}

    assert deep_merge(base, overlay) == {"a": {"b": 2, "keep": "x"}, "top": "overlay"}


def test_lists_replace_wholesale():
    base = {"vaps": [{"ssid": "one", "security": "wpa2"}, {"ssid": "two"}]}
    overlay = {"vaps": [{"ssid": "three"}]}

    # The whole list is replaced — nothing from the base list survives.
    assert deep_merge(base, overlay) == {"vaps": [{"ssid": "three"}]}


def test_scalars_and_null_replace():
    base = {"x": 1, "y": {"z": 2}}
    overlay = {"x": None, "y": "flat"}

    assert deep_merge(base, overlay) == {"x": None, "y": "flat"}


def test_overlay_only_keys_are_added():
    assert deep_merge({"a": 1}, {"b": {"c": 2}}) == {"a": 1, "b": {"c": 2}}


def test_empty_overlay_is_identity():
    base = {"a": {"b": [1, 2]}}
    assert deep_merge(base, {}) == base


def test_inputs_are_not_mutated():
    base = {"a": {"b": 1}, "l": [1]}
    overlay = {"a": {"c": 2}, "l": [2]}
    base_snapshot = copy.deepcopy(base)
    overlay_snapshot = copy.deepcopy(overlay)

    deep_merge(base, overlay)

    assert base == base_snapshot
    assert overlay == overlay_snapshot


def test_tachyon_handler_delegates_to_shared_merge():
    """The handler method that this utility was promoted from must keep
    identical semantics (it now delegates)."""
    from provisioner.handlers.tachyon import TachyonHandler

    handler = TachyonHandler("169.254.1.1", {"username": "u", "password": "p"})
    base = {"system": {"hostname": "a", "users": [{"name": "root"}]}}
    overlay = {"system": {"hostname": "b", "users": [{"name": "admin"}]}}

    assert handler._deep_merge(base, overlay) == deep_merge(base, overlay)
    assert handler._deep_merge(base, overlay) == {
        "system": {"hostname": "b", "users": [{"name": "admin"}]}
    }
