"""Tests for app.periodic — weekly rescan scheduling and cron parsing."""
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("TECHSCAN_DISABLE_DB", "1")
os.environ.setdefault("TECHSCAN_PERSIST_BROWSER", "0")


class TestCronToWeekday:
    """Test _cron_to_weekday helper."""

    def test_numeric_zero(self):
        from app.periodic import _cron_to_weekday

        # 0 = Sunday -> Python weekday 6
        assert _cron_to_weekday("0") == 6

    def test_numeric_one(self):
        from app.periodic import _cron_to_weekday

        # 1 = Monday -> Python weekday 0
        assert _cron_to_weekday("1") == 0

    def test_numeric_six(self):
        from app.periodic import _cron_to_weekday

        # 6 = Saturday -> Python weekday 5
        assert _cron_to_weekday("6") == 5

    def test_named_sun(self):
        from app.periodic import _cron_to_weekday

        assert _cron_to_weekday("sun") == 6

    def test_named_mon(self):
        from app.periodic import _cron_to_weekday

        assert _cron_to_weekday("mon") == 0

    def test_named_fri(self):
        from app.periodic import _cron_to_weekday

        assert _cron_to_weekday("fri") == 4

    def test_wildcard(self):
        from app.periodic import _cron_to_weekday

        # * means any day
        assert _cron_to_weekday("*") is None

    def test_invalid(self):
        from app.periodic import _cron_to_weekday

        with pytest.raises((ValueError, KeyError)):
            _cron_to_weekday("invalid")


class TestParseWeeklyCron:
    """Test _parse_weekly_cron parsing of cron spec."""

    def test_sunday_3am(self):
        from app.periodic import _parse_weekly_cron

        minute, hour, weekday = _parse_weekly_cron("0 3 * * 0")
        assert minute == 0
        assert hour == 3
        assert weekday == 6  # Sunday -> Python weekday 6

    def test_monday_midnight(self):
        from app.periodic import _parse_weekly_cron

        minute, hour, weekday = _parse_weekly_cron("0 0 * * 1")
        assert minute == 0
        assert hour == 0
        assert weekday == 0  # Monday

    def test_every_day_noon(self):
        from app.periodic import _parse_weekly_cron

        minute, hour, weekday = _parse_weekly_cron("30 12 * * *")
        assert minute == 30
        assert hour == 12
        assert weekday is None  # Every day

    def test_invalid_format(self):
        from app.periodic import _parse_weekly_cron

        with pytest.raises(ValueError):
            _parse_weekly_cron("bad")


class TestComputeNextRun:
    """Test _compute_next_run calculates correct future timestamps."""

    def test_next_run_is_in_future(self):
        from app.periodic import _compute_next_run

        now = time.time()
        next_run = _compute_next_run(0, 3, 6, now=now)  # Sunday 3 AM
        assert next_run > now or abs(next_run - now) < 2  # Either future or very close to now

    def test_next_run_returns_float(self):
        from app.periodic import _compute_next_run

        result = _compute_next_run(0, 3, None)
        assert isinstance(result, (int, float))

    def test_daily_schedule(self):
        from app.periodic import _compute_next_run

        now = time.time()
        result = _compute_next_run(30, 12, None, now=now)  # Every day at 12:30
        assert isinstance(result, (int, float))
        # Should be within next 24h + margin
        assert result <= now + 86400 + 60


class TestResolveNextRun:
    """Test _resolve_next_run with environment-based cron spec."""

    def test_returns_float(self, monkeypatch):
        from app.periodic import _resolve_next_run

        monkeypatch.setenv("TECHSCAN_WEEKLY_RESCAN_CRON", "0 3 * * 0")
        result = _resolve_next_run()
        assert isinstance(result, (int, float))
        assert result > 0

    def test_allow_past(self, monkeypatch):
        from app.periodic import _resolve_next_run

        monkeypatch.setenv("TECHSCAN_WEEKLY_RESCAN_CRON", "0 3 * * 0")
        result = _resolve_next_run(allow_past=True)
        assert isinstance(result, (int, float))


class TestWeeklyBudget:
    """Test _weekly_budget_ms helper."""

    def test_default_budget(self):
        from app.periodic import _weekly_budget_ms

        budget = _weekly_budget_ms()
        assert isinstance(budget, int)
        assert budget > 0

    def test_custom_budget(self, monkeypatch):
        """Custom budget via env var TECHSCAN_WEEKLY_RESCAN_BUDGET_MS."""
        from app.periodic import _weekly_budget_ms

        monkeypatch.setenv("TECHSCAN_WEEKLY_RESCAN_BUDGET_MS", "60000")
        budget = _weekly_budget_ms()
        assert budget == 60000
