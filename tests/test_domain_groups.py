"""Tests for app.domain_groups — domain grouping/assignment logic."""
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("TECHSCAN_DISABLE_DB", "1")
os.environ.setdefault("TECHSCAN_PERSIST_BROWSER", "0")


@pytest.fixture
def tmp_groups_file(monkeypatch, tmp_path):
    """Create a temporary domain_groups.json for isolated testing."""
    groups_file = tmp_path / "domain_groups.json"
    initial = {
        "groups": {"faculty": ["fk.unair.ac.id"], "directorate": ["rektorat.unair.ac.id"]},
        "version": 1,
        "updated_at": 0,
    }
    groups_file.write_text(json.dumps(initial), encoding="utf-8")
    monkeypatch.setenv("TECHSCAN_DOMAIN_GROUPS_FILE", str(groups_file))

    # Reset module-level cache so it re-reads
    import app.domain_groups as dg

    dg._groups_cache = {}
    dg._groups_mtime = None
    dg._cached_obj = None
    dg._GROUPS_PATH = str(groups_file)

    return groups_file


class TestDomainGroupsClass:
    """Test the DomainGroups data class."""

    def test_all_domains(self):
        from app.domain_groups import DomainGroups

        dg = DomainGroups(
            groups={"fac": ["a.com", "b.com"], "dir": ["c.com"]},
        )
        all_d = dg.all_domains()
        assert "a.com" in all_d
        assert "b.com" in all_d
        assert "c.com" in all_d

    def test_all_domains_deduplication(self):
        from app.domain_groups import DomainGroups

        dg = DomainGroups(groups={"g1": ["a.com"], "g2": ["a.com"]})
        all_d = dg.all_domains()
        assert all_d.count("a.com") == 1  # Should not duplicate

    def test_membership(self):
        from app.domain_groups import DomainGroups

        dg = DomainGroups(groups={"fac": ["a.com"], "dir": ["a.com", "b.com"]})
        groups = dg.membership("a.com")
        assert "fac" in groups
        assert "dir" in groups

    def test_membership_not_found(self):
        from app.domain_groups import DomainGroups

        dg = DomainGroups(groups={"fac": ["a.com"]})
        assert dg.membership("unknown.com") == []


class TestLoadAndReload:
    """Test loading and reloading domain groups from file."""

    def test_load(self, tmp_groups_file):
        from app.domain_groups import load

        result = load(force=True)
        assert result is not None
        assert "fk.unair.ac.id" in result.all_domains()

    def test_reload(self, tmp_groups_file):
        from app.domain_groups import load, reload

        load(force=True)
        result = reload()
        assert result is not None


class TestGroupMutations:
    """Test add/delete groups, assign/remove domains."""

    def test_add_group(self, tmp_groups_file):
        from app.domain_groups import add_group, load

        add_group("research")
        data = load(force=True)
        assert "research" in data.groups

    def test_add_duplicate_group(self, tmp_groups_file):
        from app.domain_groups import add_group

        add_group("faculty")  # Already exists
        # Should not raise, silently succeeds

    def test_delete_non_default_group(self, tmp_groups_file):
        """Deleting a non-default group should remove it permanently."""
        from app.domain_groups import add_group, delete_group, load

        add_group("custom_group")
        data = load(force=True)
        assert "custom_group" in data.groups

        delete_group("custom_group")
        data = load(force=True)
        assert "custom_group" not in data.groups

    def test_delete_default_group_readded(self, tmp_groups_file):
        """Default groups are re-added by _ensure_defaults, so they persist as empty."""
        from app.domain_groups import delete_group, load, DEFAULT_KEYS

        delete_group("directorate")
        data = load(force=True)
        # directorate is a DEFAULT_KEY, so _ensure_defaults re-adds it (empty)
        if "directorate" in DEFAULT_KEYS:
            assert "directorate" in data.groups
            assert data.groups["directorate"] == []  # But cleared of domains

    def test_assign_domain(self, tmp_groups_file):
        from app.domain_groups import assign_domain, load

        assign_domain("faculty", "ft.unair.ac.id")
        data = load(force=True)
        assert "ft.unair.ac.id" in data.groups["faculty"]

    def test_remove_domain(self, tmp_groups_file):
        from app.domain_groups import remove_domain, load

        remove_domain("faculty", "fk.unair.ac.id")
        data = load(force=True)
        assert "fk.unair.ac.id" not in data.groups["faculty"]

    def test_remove_domain_everywhere(self, tmp_groups_file):
        from app.domain_groups import assign_domain, remove_domain_everywhere, load

        assign_domain("directorate", "fk.unair.ac.id")
        remove_domain_everywhere("fk.unair.ac.id")
        data = load(force=True)
        for group_domains in data.groups.values():
            assert "fk.unair.ac.id" not in group_domains


class TestEnsureDefaults:
    """Test _ensure_defaults fills missing group keys."""

    def test_adds_default_keys(self):
        from app.domain_groups import _ensure_defaults, DEFAULT_KEYS

        data = {"groups": {}}
        _ensure_defaults(data)
        for key in DEFAULT_KEYS:
            assert key in data["groups"]

    def test_preserves_existing(self):
        from app.domain_groups import _ensure_defaults

        data = {"groups": {"faculty": ["a.com"]}}
        _ensure_defaults(data)
        assert data["groups"]["faculty"] == ["a.com"]


class TestGroupDomains:
    """Test group_domains function that organizes domain metadata."""

    def test_basic_grouping(self, tmp_groups_file):
        from app.domain_groups import group_domains, load

        load(force=True)
        meta = [("fk.unair.ac.id", 1000000, "unified", 10)]
        result = group_domains(meta)
        assert isinstance(result, dict)

    def test_empty_input(self, tmp_groups_file):
        from app.domain_groups import group_domains, load

        load(force=True)
        result = group_domains([])
        assert isinstance(result, dict)


class TestDiagnostics:
    """Test diagnostics function."""

    def test_returns_dict(self, tmp_groups_file):
        from app.domain_groups import diagnostics, load

        load(force=True)
        diag = diagnostics()
        assert isinstance(diag, dict)
