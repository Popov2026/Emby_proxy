#!/usr/bin/env python3
"""Suite de tests d'emby_quota.py (moteur de quotas integre a Emby Proxy).

Les tests de la fenetre DearPyGui, de la console, du service Windows et de
ses installeurs ne sont pas repris : le proxy et sa page d'administration
remplacent ces interfaces.

Les tests tournent contre mock_emby.MockEmby (vrai serveur HTTP local), donc
la couche transport est reellement exercee - aucune requete ne part vers un
serveur Emby de production. L'horloge est injectee pour rendre les scenarios
temporels deterministes et instantanes.

    python3 -m unittest discover -v
"""

from __future__ import annotations

import configparser
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime

import emby_quota as eq
from mock_emby import MockEmby

T0 = datetime(2026, 9, 6, 12, 0, 0).timestamp()  # dimanche 06/09/2026 12:00


REAL_SETUP_LOGGING = eq.setup_logging


def setUpModule() -> None:
    """Le daemon logue beaucoup : on garde la sortie des tests lisible."""
    eq.LOG.handlers.clear()
    eq.LOG.addHandler(logging.NullHandler())
    eq.LOG.propagate = False
    eq.setup_logging = lambda cfg: None  # neutralise la reconfiguration via main()


def _silence_logger() -> None:
    eq.LOG.handlers.clear()
    eq.LOG.addHandler(logging.NullHandler())
    eq.LOG.propagate = False
    eq.LOG.setLevel(logging.INFO)


class Clock:
    """Horloge injectable."""

    def __init__(self, start: float = T0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_config(**overrides) -> eq.Config:
    cfg = eq.Config(
        url="http://127.0.0.1:1",
        api_key="test-key",
        poll_interval=20,
        db_path=":memory:",
        log_path="",
        default_minutes=120,
        period="daily",
        reset_time="04:00",
        grace_seconds=0,
        warn_at_minutes=[10, 5, 1],
        # actif par defaut dans le produit ; neutralise ici pour que les tests
        # qui n'en parlent pas ne recoivent pas ce message. TestTooShort le
        # reactive, et TestDefaultsAreStrict verifie le defaut livre.
        warn_if_too_short=False,
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def make_user_view(
    name: str = "Enfant1",
    used: float = 0.0,
    quota: float = 3600.0,
    bonus: float = 0.0,
    stop_count: int = 0,
    exempt: str = "",
    disabled_until=None,
    scopes=None,
) -> eq.UserView:
    """UserView minimale pour les tests d'affichage."""
    user = eq.UserView(
        user_id="u", user_name=name, exempt=exempt, disabled_until=disabled_until
    )
    if scopes is None:
        scopes = {"daily": (used, quota, bonus, stop_count)}
    for scope, (u, q, b, s) in scopes.items():
        user.scopes[scope] = eq.ScopeView(
            scope=scope, used=u, quota=q, bonus=b, stop_count=s
        )
    limites = [v for v in user.scopes.values() if v.limited]
    if limites and not exempt:
        user.binding = min(limites, key=lambda v: v.remaining).scope
    return user


class BaseCase(unittest.TestCase):
    """Monte un faux serveur Emby + un moniteur relie a une base en memoire."""

    config_overrides: dict = {}

    def setUp(self) -> None:
        self.emby = MockEmby(api_key="test-key").start()
        self.addCleanup(self.emby.stop)
        self.emby.add_user("u-adm", "Alice", admin=True)
        self.emby.add_user("u-kid", "Enfant1")

        self.clock = Clock()
        self.cfg = make_config(url=self.emby.url, **self.config_overrides)
        self.cfg.validate()
        self.store = eq.Store(":memory:")
        self.addCleanup(self.store.close)
        self.api = eq.EmbyApi(self.cfg.url, self.cfg.api_key)
        self.monitor = eq.Monitor(self.cfg, self.api, self.store, clock=self.clock)

    # -- helpers -----------------------------------------------------------

    def tick(self, advance: float = 0.0) -> None:
        if advance:
            self.clock.advance(advance)
        self.monitor.tick()

    def now(self) -> datetime:
        """L'heure du moniteur, pas celle du systeme : les tests restent
        deterministes meme si la vraie date change de journee en cours de run."""
        return datetime.fromtimestamp(self.clock())

    def usage(self, user_id: str = "u-kid") -> eq.UsageRow:
        pkey = eq.period_key(datetime.fromtimestamp(self.clock()), self.cfg)
        return self.store.get_usage(user_id, pkey)


# ---------------------------------------------------------------------------


class TestPeriodBounds(unittest.TestCase):
    def test_daily_after_reset(self):
        cfg = make_config(period="daily", reset_time="04:00")
        start, end = eq.period_bounds(datetime(2026, 9, 6, 12, 0), cfg)
        self.assertEqual(start, datetime(2026, 9, 6, 4, 0))
        self.assertEqual(end, datetime(2026, 9, 7, 4, 0))

    def test_daily_before_reset_belongs_to_previous_day(self):
        cfg = make_config(period="daily", reset_time="04:00")
        start, end = eq.period_bounds(datetime(2026, 9, 6, 2, 30), cfg)
        self.assertEqual(start, datetime(2026, 9, 5, 4, 0))
        self.assertEqual(end, datetime(2026, 9, 6, 4, 0))

    def test_weekly_anchors_on_monday(self):
        cfg = make_config(period="weekly", reset_time="04:00", reset_weekday=0)
        start, end = eq.period_bounds(datetime(2026, 9, 6, 12, 0), cfg)  # dimanche
        self.assertEqual(start, datetime(2026, 8, 31, 4, 0))  # lundi precedent
        self.assertEqual(end, datetime(2026, 9, 7, 4, 0))

    def test_monthly_wraps_over_year(self):
        cfg = make_config(period="monthly", reset_time="04:00", reset_day=1)
        start, end = eq.period_bounds(datetime(2027, 1, 1, 2, 0), cfg)
        self.assertEqual(start, datetime(2026, 12, 1, 4, 0))
        self.assertEqual(end, datetime(2027, 1, 1, 4, 0))

    def test_key_changes_across_boundary(self):
        cfg = make_config(period="daily", reset_time="04:00")
        before = eq.period_key(datetime(2026, 9, 7, 3, 59), cfg)
        after = eq.period_key(datetime(2026, 9, 7, 4, 1), cfg)
        self.assertNotEqual(before, after)


class TestAccounting(BaseCase):
    def test_first_observation_is_not_billed(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.assertEqual(self.usage().seconds, 0.0)

    def test_wall_clock_delta_accumulates(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 40.0, places=3)

    def test_paused_session_not_counted(self):
        session = self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 20.0)
        session["PlayState"]["IsPaused"] = True
        self.tick(20)
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 20.0)
        # a la reprise, on repart d'une observation neutre
        session["PlayState"]["IsPaused"] = False
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 20.0)
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 40.0)

    def test_paused_counted_when_configured(self):
        self.cfg.count_paused = True
        session = self.emby.add_session("s1", "u-kid", "Enfant1")
        session["PlayState"]["IsPaused"] = True
        self.tick()
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 20.0)

    def test_idle_session_without_item_not_counted(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick()
        self.tick(20)
        self.assertEqual(self.usage().seconds, 0.0)

    def test_large_gap_is_clamped(self):
        """Daemon arrete ou machine en veille : on ne facture pas le trou."""
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(3600)
        self.assertAlmostEqual(self.usage().seconds, 60.0)  # 3 x poll_interval

    def test_concurrent_streams_counted_once_by_default(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", device="TV")
        self.emby.add_session("s2", "u-kid", "Enfant1", device="Tablette")
        self.tick()
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 20.0)

    def test_concurrent_streams_summed_when_configured(self):
        self.cfg.count_concurrent_streams = True
        self.emby.add_session("s1", "u-kid", "Enfant1", device="TV")
        self.emby.add_session("s2", "u-kid", "Enfant1", device="Tablette")
        self.tick()
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 40.0)


class TestExemptions(BaseCase):
    def test_an_administrator_is_counted_like_anyone_else(self):
        """Aucune exemption automatique : le statut admin ne dispense de rien."""
        self.emby.add_session("s1", "u-adm", "Alice")
        self.tick()
        self.tick(20)
        self.assertAlmostEqual(self.usage("u-adm").seconds, 20.0)

    def test_an_administrator_can_be_exempted_by_name(self):
        self.monitor.reload_config(
            make_config(url=self.emby.url, exempt_users=["Alice"])
        )
        self.emby.add_session("s1", "u-adm", "Alice")
        self.tick()
        self.tick(20)
        self.assertEqual(self.usage("u-adm").seconds, 0.0)

    def test_named_user_is_exempt(self):
        self.monitor._exempt_names = {"enfant1"}
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        self.assertEqual(self.usage().seconds, 0.0)

    def test_lan_network_is_exempt(self):
        import ipaddress

        self.monitor._exempt_nets = [ipaddress.ip_network("192.168.1.0/24")]
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", endpoint="192.168.1.42:5000"
        )
        self.tick()
        self.tick(20)
        self.assertEqual(self.usage().seconds, 0.0)

    def test_wan_session_still_counted_with_lan_exemption(self):
        import ipaddress

        self.monitor._exempt_nets = [ipaddress.ip_network("192.168.1.0/24")]
        self.emby.add_session("s1", "u-kid", "Enfant1", endpoint="82.64.10.3:5000")
        self.tick()
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 20.0)

    def test_parse_ip_formats(self):
        self.assertEqual(str(eq.Monitor._parse_ip("192.168.1.5:51234")), "192.168.1.5")
        self.assertEqual(str(eq.Monitor._parse_ip("[::1]:8096")), "::1")
        self.assertEqual(str(eq.Monitor._parse_ip("10.0.0.1")), "10.0.0.1")
        self.assertIsNone(eq.Monitor._parse_ip(""))
        self.assertIsNone(eq.Monitor._parse_ip("nimportequoi"))


class TestWarnings(BaseCase):
    config_overrides = {"default_minutes": 2, "warn_at_minutes": [1]}

    def test_warning_sent_once_per_threshold(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()          # 0 s
        self.tick(20)        # 20 s -> reste 100 s
        self.assertEqual(len(self.emby.messages), 0)
        self.tick(20)        # 40 s -> reste 80 s
        self.assertEqual(len(self.emby.messages), 0)
        self.tick(20)        # 60 s -> reste 60 s = palier 1 min
        self.assertEqual(len(self.emby.messages), 1)
        header, body = self.emby.messages[0][1]["Header"], self.emby.messages[0][1]["Text"]
        self.assertEqual(header, self.cfg.warn_header)
        self.assertIn("1", body)
        self.tick(20)        # 80 s -> pas de second message pour le meme palier
        self.assertEqual(len(self.emby.messages), 1)

    def test_skipped_thresholds_do_not_spam(self):
        """Demarrage tardif : un seul message meme si plusieurs paliers sont franchis."""
        self.cfg.default_minutes = 100
        self.cfg.warn_at_minutes = [10, 5, 1]
        row = self.usage()
        row.user_name = "Enfant1"
        row.seconds = 97 * 60  # reste 3 minutes
        self.store.save_usage(row)
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.assertEqual(self.usage().warned_tokens(), {"m10", "m5"})
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)

    def test_message_reaches_every_device_of_the_user(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", device="TV")
        self.emby.add_session("s2", "u-kid", "Enfant1", device="Tablette")
        self.tick()
        self.tick(60)
        self.assertEqual({m[0] for m in self.emby.messages}, {"s1", "s2"})


class TestEnforcement(BaseCase):
    config_overrides = {"default_minutes": 1, "warn_at_minutes": [], "grace_seconds": 0}

    def test_stop_sent_when_quota_reached(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        self.tick(20)
        self.assertEqual(self.emby.playstate, [])
        self.tick(20)  # 60 s = quota
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])
        # sans delai de grace, pas de preavis : seul le message de coupure part
        self.assertEqual(len(self.emby.messages), 1)
        self.assertEqual(self.emby.messages[0][1]["Header"], self.cfg.stopped_header)
        self.assertEqual(self.usage().stop_count, 1)

    def test_grace_delays_the_stop_by_one_cycle(self):
        self.cfg.grace_seconds = 15
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        self.tick(20)
        self.tick(20)  # quota atteint : message seul
        self.assertEqual(len(self.emby.messages), 1)
        self.assertEqual(self.emby.playstate, [])
        self.tick(20)  # fin du delai de grace : coupure
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])

    def test_all_sessions_of_the_user_are_stopped(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", device="TV")
        self.emby.add_session("s2", "u-kid", "Enfant1", device="Tablette")
        self.tick()
        self.tick(60)
        self.assertEqual({p[0] for p in self.emby.playstate}, {"s1", "s2"})

    def test_other_users_untouched(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.emby.add_session("s2", "u-adm", "Alice")
        row = self.usage()
        row.user_name = "Enfant1"
        row.seconds = 120
        self.store.save_usage(row)
        self.tick()
        self.assertEqual([p[0] for p in self.emby.playstate], ["s1"])

    def test_restart_after_stop_is_counted(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)
        self.assertEqual(self.usage().stop_count, 1)
        self.emby.add_session("s2", "u-kid", "Enfant1")  # relance
        self.tick(20)
        self.assertEqual(self.usage().stop_count, 2)

    def test_unlimited_user_is_never_stopped(self):
        self.cfg.default_minutes = 0
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(600)
        self.assertEqual(self.emby.playstate, [])

    def test_dry_run_sends_nothing(self):
        self.cfg.dry_run = True
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)
        self.assertEqual(self.emby.messages, [])
        self.assertEqual(self.emby.playstate, [])
        self.assertEqual(self.usage().stop_count, 1)  # comptabilise quand meme


class TestEscalation(BaseCase):
    config_overrides = {
        "default_minutes": 1,
        "warn_at_minutes": [],
        "grace_seconds": 0,
        "escalation": "disable_user",
        "escalation_after_restarts": 1,
    }

    def test_account_disabled_after_repeated_restarts(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)                                   # coupure #1
        self.assertEqual(self.emby.policy_updates, [])
        self.emby.add_session("s2", "u-kid", "Enfant1")  # relance
        self.tick(20)                                   # coupure #2 -> escalade
        self.assertEqual(len(self.emby.policy_updates), 1)
        user_id, policy = self.emby.policy_updates[0]
        self.assertEqual(user_id, "u-kid")
        self.assertTrue(policy["IsDisabled"])
        # le reste de la policy doit etre preserve
        self.assertTrue(policy["EnableAllFolders"])
        self.assertFalse(policy["IsAdministrator"])

    def test_account_reenabled_at_period_end(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)
        self.emby.add_session("s2", "u-kid", "Enfant1")
        self.tick(20)
        self.assertEqual(len(self.store.disabled_rows()), 1)
        # on saute au lendemain, apres l'heure de reset
        self.clock.advance(24 * 3600)
        self.monitor.tick()
        self.assertEqual(len(self.store.disabled_rows()), 0)
        self.assertFalse(self.emby.policy_updates[-1][1]["IsDisabled"])

    def test_temporary_disable_window(self):
        self.cfg.escalation_minutes = 30
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)
        self.emby.add_session("s2", "u-kid", "Enfant1")
        self.tick(20)
        until = self.store.disabled_rows()[0]["until_ts"]
        self.assertAlmostEqual(until, self.clock() + 30 * 60, delta=1)
        self.clock.advance(29 * 60)
        self.monitor.tick()
        self.assertEqual(len(self.store.disabled_rows()), 1)
        self.clock.advance(2 * 60)
        self.monitor.tick()
        self.assertEqual(len(self.store.disabled_rows()), 0)


class TestPeriodRollover(BaseCase):
    config_overrides = {"default_minutes": 5, "warn_at_minutes": []}

    def test_counter_resets_on_new_period(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)
        self.assertAlmostEqual(self.usage().seconds, 60.0)
        old_key = eq.period_key(datetime.fromtimestamp(self.clock()), self.cfg)
        self.clock.advance(20 * 3600)  # le lendemain 08:00, apres reset 04:00
        self.monitor.tick()
        new_key = eq.period_key(datetime.fromtimestamp(self.clock()), self.cfg)
        self.assertNotEqual(old_key, new_key)
        self.assertLessEqual(self.usage().seconds, 60.0)
        self.assertEqual(self.store.get_usage("u-kid", old_key).seconds, 60.0)


class TestBonus(BaseCase):
    config_overrides = {"default_minutes": 1, "warn_at_minutes": [], "grace_seconds": 0}

    def test_bonus_extends_the_quota(self):
        row = self.usage()
        row.user_name = "Enfant1"
        row.bonus_secs = 120
        self.store.save_usage(row)
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)   # 60 s consommees, quota effectif 180 s
        self.assertEqual(self.emby.playstate, [])
        self.tick(60)
        self.tick(60)   # 180 s
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])


class TestHttpLayer(unittest.TestCase):
    def setUp(self) -> None:
        self.emby = MockEmby(api_key="secret").start()
        self.addCleanup(self.emby.stop)
        self.emby.add_user("u1", "Alice", admin=True)
        self.api = eq.EmbyApi(self.emby.url, "secret")

    def test_sessions_and_users(self):
        self.emby.add_session("s1", "u1", "Alice")
        self.assertEqual(len(self.api.sessions()), 1)
        self.assertEqual(len(self.api.users()), 1)

    def test_message_payload(self):
        self.api.send_message("s1", "Titre", "Corps", 5000)
        self.assertEqual(
            self.emby.messages[0][1],
            {"Header": "Titre", "Text": "Corps", "TimeoutMs": 5000},
        )

    def test_playstate_path(self):
        self.api.playstate("s1", "Stop")
        self.assertIn(("POST", "/Sessions/s1/Playing/Stop", None), self.emby.calls)

    def test_policy_round_trip_preserves_fields(self):
        self.api.set_user_disabled("u1", True)
        policy = self.emby.users["u1"]["Policy"]
        self.assertTrue(policy["IsDisabled"])
        self.assertTrue(policy["IsAdministrator"])
        self.assertIn("BlockedTags", policy)

    def test_bad_key_raises(self):
        api = eq.EmbyApi(self.emby.url, "mauvaise-cle")
        with self.assertRaises(eq.EmbyError):
            api.sessions()

    def test_unreachable_server_raises(self):
        api = eq.EmbyApi("http://127.0.0.1:9", "secret", timeout=1)
        with self.assertRaises(eq.EmbyError):
            api.sessions()


class TestConfig(unittest.TestCase):
    def _write(self, body: str) -> str:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False, encoding="utf-8"
        )
        handle.write(body)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_full_parse(self):
        path = self._write(
            """
[server]
url = http://nas:8096
api_key = abc123
[daemon]
poll_interval = 30
[quota]
period = weekly
default_minutes = 300
exempt_users = Alice, Invite
exempt_networks = 192.168.1.0/24
[enforcement]
warn_at_minutes = 15, 5
escalation = disable_user
[users]
Enfant1 = 60
Enfant2 = 90
"""
        )
        cfg = eq.load_config(path)
        self.assertEqual(cfg.url, "http://nas:8096")
        self.assertEqual(cfg.poll_interval, 30)
        self.assertEqual(cfg.period, "weekly")
        self.assertEqual(cfg.exempt_users, ["Alice", "Invite"])
        self.assertEqual(cfg.warn_at_minutes, [15, 5])
        self.assertEqual(cfg.user_quotas, {"enfant1": {"daily": 60}, "enfant2": {"daily": 90}})
        self.assertEqual(cfg.escalation, "disable_user")

    def test_missing_api_key_is_rejected(self):
        path = self._write("[server]\nurl = http://nas:8096\n")
        with self.assertRaises(ValueError):
            eq.load_config(path)

    def test_invalid_period_is_rejected(self):
        path = self._write("[server]\napi_key = k\n[quota]\nperiod = hourly\n")
        with self.assertRaises(ValueError):
            eq.load_config(path)

    def test_invalid_reset_time_is_rejected(self):
        path = self._write("[server]\napi_key = k\n[quota]\nreset_time = 25h\n")
        with self.assertRaises(ValueError):
            eq.load_config(path)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            eq.load_config("/nexistepas/emby_quota.ini")

    def test_shipped_example_is_valid(self):
        """Le fichier d'exemple livre doit se charger sans erreur."""
        example = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "emby_quota.ini.example")
        cfg = eq.load_config(example)
        self.assertEqual(cfg.tracked_scopes, ["daily", "weekly", "monthly"])
        self.assertEqual(cfg.quota_minutes("daily"), 120)
        self.assertEqual(cfg.quota_minutes("weekly"), 600)
        self.assertEqual(cfg.quota_minutes("monthly"), 0)
        self.assertTrue(cfg.warn_on_login)
        self.assertFalse(cfg.warn_on_start)
        self.assertEqual(cfg.login_cooldown_minutes, 60)
        self.assertIn("%resume%", cfg.login_text)
        self.assertEqual(cfg.warn_at_percent, [80])
        self.assertEqual(cfg.warn_at_minutes, [5])
        self.assertEqual(cfg.timeout_seconds("login"), 15)
        self.assertEqual(cfg.timeout_seconds("stop"), 20)
        # les gabarits contiennent des % : l'interpolation INI doit rester off
        self.assertIn("%pourcentage%", cfg.warn_text)


class TestCli(unittest.TestCase):
    def setUp(self) -> None:
        self.emby = MockEmby(api_key="k").start()
        self.addCleanup(self.emby.stop)
        self.emby.add_user("u-kid", "Enfant1")
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "quota.db")
        self.ini = os.path.join(self.tmp, "emby_quota.ini")
        with open(self.ini, "w", encoding="utf-8") as handle:
            handle.write(
                f"[server]\nurl = {self.emby.url}\napi_key = k\n"
                f"[daemon]\ndb_path = {self.db}\nlog_path =\n"
                f"[quota]\ndefault_minutes = 60\n"
                f"[enforcement]\ngrace_seconds = 0\n"
            )

    def test_test_connection(self):
        self.assertEqual(eq.main(["--config", self.ini, "--test-connection"]), 0)

    def test_settings_lists_every_key(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = eq.main(["--config", self.ini, "--settings"])
        self.assertEqual(code, 0)
        sortie = buffer.getvalue()
        for cle in (
            "message_timeout_seconds",
            "login_timeout_seconds",
            "stop_timeout_seconds",
            "tooshort_timeout_seconds",
            "warn_on_login",
            "warn_if_too_short",
            "daily_minutes",
            "language",
            "grace_seconds",
            "login_text",
        ):
            self.assertIn(cle, sortie, f"{cle} absent de --settings")
        self.assertNotIn("k", sortie.split("api_key")[1].split("\n")[0])  # cle masquee

    def test_settings_shows_the_effective_values(self):
        import contextlib
        import io

        eq.update_ini(self.ini, {"enforcement": {"login_timeout_seconds": "42"}})
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            eq.main(["--config", self.ini, "--settings"])
        self.assertIn("login_timeout_seconds        42", buffer.getvalue())

    def test_grant_then_status(self):
        self.assertEqual(
            eq.main(["--config", self.ini, "--grant", "Enfant1", "30"]), 0
        )
        store = eq.Store(self.db)
        pkey = eq.period_key(datetime.now(), eq.load_config(self.ini))
        self.assertEqual(store.get_usage("u-kid", pkey).bonus_secs, 1800)
        store.close()
        self.assertEqual(eq.main(["--config", self.ini, "--status"]), 0)

    def test_reset_clears_counter(self):
        cfg = eq.load_config(self.ini)
        pkey = eq.period_key(datetime.now(), cfg)
        store = eq.Store(self.db)
        store.save_usage(
            eq.UsageRow(user_id="u-kid", period_key=pkey, user_name="Enfant1", seconds=999)
        )
        store.close()
        self.assertEqual(eq.main(["--config", self.ini, "--reset", "Enfant1"]), 0)
        store = eq.Store(self.db)
        self.assertEqual(store.get_usage("u-kid", pkey).seconds, 0.0)
        store.close()

    def test_once_runs_a_single_cycle(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.assertEqual(eq.main(["--config", self.ini, "--once"]), 0)
        self.assertIn(("GET", "/Sessions", None), self.emby.calls)

    def test_unknown_user_exits(self):
        with self.assertRaises(SystemExit):
            eq.main(["--config", self.ini, "--grant", "Inconnu", "10"])

    def test_bad_config_returns_2(self):
        self.assertEqual(eq.main(["--config", "/nexistepas.ini", "--status"]), 2)

    def test_greet_sends_a_message_to_open_sessions(self):
        import contextlib
        import io

        eq.update_ini(self.ini, {"enforcement": {"warn_on_login": "true"}})
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = eq.main(["--config", self.ini, "--greet"])
        self.assertEqual(code, 0)
        self.assertEqual(len(self.emby.messages), 1)
        self.assertIn("Enfant1", buffer.getvalue())

    def test_greet_sends_every_repetition_before_exiting(self):
        """Le processus ne doit pas mourir avant d'avoir envoye les repetitions :
        --greet afficherait une fois la ou le daemon affiche trois fois."""
        import contextlib
        import io

        eq.update_ini(
            self.ini,
            {"enforcement": {"warn_on_login": "true",
                             "login_repeat_count": "3",
                             "message_repeat_interval_seconds": "0.05"}},
        )
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = eq.main(["--config", self.ini, "--greet"])
        self.assertEqual(code, 0)
        self.assertEqual(len(self.emby.messages), 3)
        self.assertIn("3 affichage(s) envoye(s)", buffer.getvalue())

    def test_greet_says_when_a_single_display_is_configured(self):
        import contextlib
        import io

        eq.update_ini(self.ini, {"enforcement": {"warn_on_login": "true"}})
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            eq.main(["--config", self.ini, "--greet"])
        self.assertEqual(len(self.emby.messages), 1)
        self.assertIn("login_repeat_count = 4", buffer.getvalue())

    def test_greet_without_session_returns_1(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = eq.main(["--config", self.ini, "--greet"])
        self.assertEqual(code, 1)
        self.assertIn("Aucune session ouverte", buffer.getvalue())

    def test_status_shows_the_login_cooldown(self):
        import contextlib
        import io

        eq.update_ini(
            self.ini,
            {"enforcement": {"warn_on_login": "true",
                             "login_cooldown_enabled": "true",
                             "login_cooldown_minutes": "60"}},
        )
        store = eq.Store(self.db)
        store.log_event(time.time() - 600, "u-kid", "Enfant1", "login", "1h00")
        store.close()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(eq.main(["--config", self.ini, "--status"]), 0)
        sortie = buffer.getvalue()
        self.assertIn("Accueil a la connexion", sortie)
        self.assertIn("Enfant1", sortie.split("Accueil a la connexion")[1])
        self.assertIn("bloque, prochain a", sortie)
        self.assertIn("--greet", sortie)

    def test_status_says_when_the_cooldown_is_off(self):
        """Etat par defaut : rien dans l'INI, l'anti-rebond ne s'applique pas."""
        import contextlib
        import io

        eq.update_ini(self.ini, {"enforcement": {"warn_on_login": "true"}})
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            eq.main(["--config", self.ini, "--status"])
        self.assertIn("anti-rebond desactive", buffer.getvalue())

    def test_settings_exposes_the_cooldown_switch(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            eq.main(["--config", self.ini, "--settings"])
        self.assertIn("login_cooldown_enabled", buffer.getvalue())


class TestDaemonLoop(BaseCase):
    config_overrides = {"poll_interval": 5, "default_minutes": 1, "grace_seconds": 0}

    def test_run_forever_ticks_then_stops_cleanly(self):
        """La boucle execute au moins un cycle puis sort sur le drapeau d'arret."""
        self.emby.add_session("s1", "u-kid", "Enfant1")
        ticks = {"n": 0}
        original = self.monitor.tick

        def counting_tick():
            ticks["n"] += 1
            original()

        self.monitor.tick = counting_tick
        self.monitor.run_forever(lambda: ticks["n"] >= 1)
        self.assertEqual(ticks["n"], 1)
        self.assertIn(("GET", "/Sessions", None), self.emby.calls)

    def test_exception_in_a_cycle_does_not_kill_the_loop(self):
        self.cfg.poll_interval = 1  # raccourcit l'attente entre les deux cycles
        calls = {"n": 0}

        def exploding_tick():
            calls["n"] += 1
            raise RuntimeError("panne simulee")

        self.monitor.tick = exploding_tick
        self.monitor.run_forever(lambda: calls["n"] >= 2)
        self.assertEqual(calls["n"], 2)


class TestVerbose(BaseCase):
    config_overrides = {"default_minutes": 60, "warn_at_minutes": [10, 5, 1]}

    def test_cycle_report_at_debug_level(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", item="Le Grand Bleu")
        self.monitor.tick()
        with self.assertLogs(eq.LOG, level=logging.DEBUG) as captured:
            self.tick(20)
        text = "\n".join(captured.output)
        self.assertIn("== cycle #2 ==", text)
        self.assertIn("periode daily", text)
        self.assertIn("LECTURE", text)
        self.assertIn("Le Grand Bleu", text)
        self.assertIn("+20s", text)
        self.assertIn("-> Enfant1", text)
        self.assertIn("restant", text)
        self.assertIn("palier 10 min", text)

    def test_exempt_session_explains_why(self):
        self.monitor.reload_config(
            make_config(url=self.emby.url, exempt_users=["Alice"])
        )
        self.emby.add_session("s1", "u-adm", "Alice")
        with self.assertLogs(eq.LOG, level=logging.DEBUG) as captured:
            self.monitor.tick()
        text = "\n".join(captured.output)
        self.assertIn("IGNOREE", text)
        self.assertIn("utilisateur exempte", text)

    def test_http_calls_traced_at_level_2(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        with self.assertLogs(eq.LOG, level=eq.TRACE) as captured:
            self.monitor.tick()
        text = "\n".join(captured.output)
        self.assertIn("HTTP GET /Sessions -> 200", text)
        self.assertIn("ms (", text)

    def test_idle_sessions_only_shown_at_level_2(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        with self.assertLogs(eq.LOG, level=eq.TRACE) as captured:
            self.monitor.tick()
        self.assertIn("INACTIVE", "\n".join(captured.output))
        with self.assertLogs(eq.LOG, level=logging.DEBUG) as captured:
            self.monitor.tick()
        self.assertNotIn("INACTIVE", "\n".join(captured.output))

    def test_paused_session_labelled(self):
        session = self.emby.add_session("s1", "u-kid", "Enfant1")
        session["PlayState"]["IsPaused"] = True
        with self.assertLogs(eq.LOG, level=eq.TRACE) as captured:
            self.monitor.tick()
        self.assertIn("PAUSE", "\n".join(captured.output))

    def test_clamped_gap_is_explained(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.monitor.tick()
        with self.assertLogs(eq.LOG, level=logging.DEBUG) as captured:
            self.tick(3600)
        self.assertIn("plafonne", "\n".join(captured.output))

    def test_next_step_labels(self):
        row = eq.UsageRow(user_id="u-kid", period_key="p", user_name="Enfant1")
        self.assertIn("palier 10 min", self.monitor._next_step(row, 20 * 60, 0))
        row.warned = "m10,m5,m1"
        self.assertIn("quota atteint dans", self.monitor._next_step(row, 20 * 60, 0))
        self.assertIn("QUOTA ATTEINT", self.monitor._next_step(row, 0, 0))
        self.monitor._pending_stop["u-kid"] = 100.0
        self.assertIn("COUPURE dans 40s", self.monitor._next_step(row, -5, 60.0))

    def test_config_dump_masks_the_api_key(self):
        cfg = make_config(api_key="ABCD1234567890EF", verbose=2)
        with self.assertLogs(eq.LOG, level=logging.DEBUG) as captured:
            eq.log_effective_config(cfg)
        text = "\n".join(captured.output)
        self.assertNotIn("ABCD1234567890EF", text)
        self.assertIn("ABCD...EF", text)
        self.assertIn("scrutation", text)
        self.assertIn("paliers", text)


class TestVerboseWiring(unittest.TestCase):
    def tearDown(self) -> None:
        _silence_logger()

    def test_levels(self):
        for verbose, expected in ((0, logging.INFO), (1, logging.DEBUG), (2, eq.TRACE)):
            REAL_SETUP_LOGGING(make_config(verbose=verbose, log_path=""))
            self.assertEqual(eq.LOG.level, expected, f"verbose={verbose}")

    def test_log_level_respected_when_not_verbose(self):
        REAL_SETUP_LOGGING(make_config(verbose=0, log_level="WARNING", log_path=""))
        self.assertEqual(eq.LOG.level, logging.WARNING)

    def test_cli_flag_counts(self):
        parser = eq.build_parser()
        self.assertEqual(parser.parse_args([]).verbose, 0)
        self.assertEqual(parser.parse_args(["-v"]).verbose, 1)
        self.assertEqual(parser.parse_args(["-vv"]).verbose, 2)
        self.assertEqual(parser.parse_args(["--verbose", "--verbose"]).verbose, 2)

    def test_invalid_verbose_in_config_is_rejected(self):
        cfg = make_config(verbose=3)
        with self.assertRaises(ValueError):
            cfg.validate()


class TestParseUserQuota(unittest.TestCase):
    def test_single_value_is_daily(self):
        self.assertEqual(eq.parse_user_quota("60"), {"daily": 60})

    def test_slash_notation(self):
        self.assertEqual(
            eq.parse_user_quota("60/300/1200"),
            {"daily": 60, "weekly": 300, "monthly": 1200},
        )
        self.assertEqual(eq.parse_user_quota("60/300"), {"daily": 60, "weekly": 300})

    def test_dash_inherits_the_default(self):
        self.assertEqual(eq.parse_user_quota("-/300/-"), {"weekly": 300})
        self.assertEqual(eq.parse_user_quota("//1200"), {"monthly": 1200})

    def test_zero_means_unlimited_for_that_scope(self):
        self.assertEqual(eq.parse_user_quota("0/300"), {"daily": 0, "weekly": 300})

    def test_explicit_notation(self):
        self.assertEqual(
            eq.parse_user_quota("daily=60, monthly=1200"),
            {"daily": 60, "monthly": 1200},
        )
        self.assertEqual(eq.parse_user_quota("jour=45, semaine=200"),
                         {"daily": 45, "weekly": 200})

    def test_empty_and_invalid(self):
        self.assertEqual(eq.parse_user_quota(""), {})
        with self.assertRaises(ValueError):
            eq.parse_user_quota("10/20/30/40")
        with self.assertRaises(ValueError):
            eq.parse_user_quota("annee=10")
        with self.assertRaises(ValueError):
            eq.parse_user_quota("beaucoup")


class TestMultiScopeConfig(unittest.TestCase):
    def test_compat_mode_tracks_only_the_legacy_period(self):
        cfg = make_config(period="weekly", default_minutes=300)
        self.assertEqual(cfg.tracked_scopes, ["weekly"])
        self.assertEqual(cfg.quota_minutes("weekly"), 300)
        self.assertEqual(cfg.quota_minutes("daily"), 0)

    def test_explicit_durations_take_over(self):
        cfg = make_config(daily_minutes=120, weekly_minutes=600, monthly_minutes=0)
        self.assertEqual(cfg.tracked_scopes, ["daily", "weekly", "monthly"])
        self.assertEqual(cfg.quota_minutes("daily"), 120)
        self.assertEqual(cfg.quota_minutes("weekly"), 600)
        self.assertEqual(cfg.quota_minutes("monthly"), 0)  # suivi mais sans limite

    def test_partial_configuration(self):
        cfg = make_config(weekly_minutes=600)
        self.assertEqual(cfg.tracked_scopes, ["weekly"])
        self.assertEqual(cfg.quota_minutes("daily"), 0)

    def test_user_quota_adds_a_tracked_scope(self):
        cfg = make_config(daily_minutes=120, user_quotas={"enfant1": {"monthly": 1200}})
        self.assertEqual(cfg.tracked_scopes, ["daily", "monthly"])
        self.assertEqual(cfg.quota_minutes("monthly", "Enfant1"), 1200)
        self.assertEqual(cfg.quota_minutes("monthly", "Autre"), 0)
        self.assertEqual(cfg.quota_minutes("daily", "Enfant1"), 120)

    def test_user_quota_is_case_insensitive(self):
        cfg = make_config(daily_minutes=120, user_quotas={"enfant1": {"daily": 45}})
        self.assertEqual(cfg.quota_minutes("daily", "ENFANT1"), 45)

    def test_scope_keys_are_distinct(self):
        cfg = make_config(daily_minutes=60, weekly_minutes=300)
        now = datetime(2026, 9, 6, 12, 0)
        keys = {eq.scope_key(now, s, cfg) for s in ("daily", "weekly", "monthly")}
        self.assertEqual(len(keys), 3)
        self.assertTrue(eq.scope_key(now, "daily", cfg).startswith("daily:"))

    def test_negative_duration_is_rejected(self):
        with self.assertRaises(ValueError):
            make_config(daily_minutes=-5).validate()

    def test_invalid_percent_is_rejected(self):
        with self.assertRaises(ValueError):
            make_config(warn_at_percent=[150]).validate()
        with self.assertRaises(ValueError):
            make_config(warn_at_percent=[0]).validate()

    def test_ini_round_trip(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False, encoding="utf-8"
        )
        handle.write(
            "[server]\napi_key = k\n"
            "[quota]\ndaily_minutes = 120\nweekly_minutes = 600\n"
            "monthly_minutes = 0\n"
            "[enforcement]\nwarn_on_start = true\nwarn_at_percent = 80, 95\n"
            "[users]\nEnfant1 = 60/300/1200\nEnfant2 = -/240/-\n"
        )
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        cfg = eq.load_config(handle.name)
        self.assertEqual(cfg.tracked_scopes, ["daily", "weekly", "monthly"])
        self.assertEqual(cfg.quota_minutes("weekly"), 600)
        self.assertEqual(cfg.quota_minutes("daily", "Enfant1"), 60)
        self.assertEqual(cfg.quota_minutes("weekly", "Enfant2"), 240)
        self.assertEqual(cfg.quota_minutes("daily", "Enfant2"), 120)  # defaut
        self.assertTrue(cfg.warn_on_start)
        self.assertEqual(cfg.warn_at_percent, [80, 95])


class TestMultiScopeEnforcement(BaseCase):
    """1 minute par jour, 2 minutes par semaine : les deux comptent."""

    config_overrides = {
        "daily_minutes": 1,
        "weekly_minutes": 2,
        "monthly_minutes": 0,
        "warn_at_minutes": [],
        "grace_seconds": 0,
    }

    def scope_usage(self, scope: str, user_id: str = "u-kid") -> eq.UsageRow:
        key = eq.scope_key(datetime.fromtimestamp(self.clock()), scope, self.cfg)
        return self.store.get_usage(user_id, key)

    def test_every_scope_is_accounted(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        for scope in ("daily", "weekly", "monthly"):
            self.assertAlmostEqual(self.scope_usage(scope).seconds, 20.0, msg=scope)

    def test_the_tightest_scope_stops_playback(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        self.tick(20)
        self.assertEqual(self.emby.playstate, [])
        self.tick(20)  # 60 s : le quota du jour est atteint avant celui de la semaine
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])
        self.assertIn("jour", self.emby.messages[-1][1]["Text"].lower() + "jour")

    def test_weekly_still_blocks_after_the_daily_reset(self):
        """Le quota du jour repart a zero, celui de la semaine non."""
        # semaine ancree au jeudi : le lendemain de T0 (dimanche) reste dedans
        self.cfg.reset_weekday = 3
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)  # 60 s : jour atteint -> coupure
        self.assertEqual(len(self.emby.playstate), 1)
        # lendemain : nouvelle journee, mais toujours la meme semaine
        self.clock.advance(24 * 3600)
        self.assertEqual(self.scope_usage("daily").seconds, 0.0)
        self.assertAlmostEqual(self.scope_usage("weekly").seconds, 60.0)
        self.emby.add_session("s2", "u-kid", "Enfant1")
        self.monitor.tick()
        self.tick(60)   # +60 s -> semaine a 120 s = quota hebdo
        self.assertEqual(len(self.emby.playstate), 2)
        self.assertAlmostEqual(self.scope_usage("weekly").seconds, 120.0, delta=1)

    def test_unlimited_scope_never_binds(self):
        """monthly_minutes = 0 : suivi mais ne bloque jamais."""
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        snap = eq.build_snapshot(self.cfg, self.monitor, self.store)
        user = next(u for u in snap.users if u.user_name == "Enfant1")
        self.assertEqual(user.binding, "daily")
        self.assertFalse(user.scope("monthly").limited)
        self.assertTrue(user.scope("monthly").used > 0)

    def test_bonus_applies_to_every_scope(self):
        rows = eq.grant_bonus(self.cfg, self.store, "u-kid", "Enfant1", 30, now=self.now())
        self.assertEqual(set(rows), {"daily", "weekly", "monthly"})
        for scope in rows:
            self.assertEqual(self.scope_usage(scope).bonus_secs, 1800)

    def test_bonus_can_target_one_scope(self):
        eq.grant_bonus(self.cfg, self.store, "u-kid", "Enfant1", 30, scopes=["weekly"], now=self.now())
        self.assertEqual(self.scope_usage("weekly").bonus_secs, 1800)
        self.assertEqual(self.scope_usage("daily").bonus_secs, 0)

    def test_stop_count_is_shared_across_scopes(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)
        for scope in ("daily", "weekly", "monthly"):
            self.assertEqual(self.scope_usage(scope).stop_count, 1, msg=scope)

    def test_per_user_quota_overrides_one_scope(self):
        self.cfg.user_quotas = {"enfant1": {"daily": 0}}  # illimite au jour
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)
        self.assertEqual(self.emby.playstate, [])  # le jour ne bloque plus
        self.tick(60)   # 120 s -> quota hebdo atteint
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])


class TestWarnTriggers(BaseCase):
    config_overrides = {
        "daily_minutes": 10,
        "warn_at_minutes": [],
        "warn_at_percent": [],
        # ces tests portent sur le mecanisme des paliers, pas sur la periode :
        # on les evalue sur la journee. Le defaut produit (mensuel) est verifie
        # par TestPercentScope.
        "warn_percent_scope": "daily",
        "warn_on_start": False,
        "grace_seconds": 0,
    }

    def test_no_message_when_every_trigger_is_off(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(60)
        self.tick(60)
        self.assertEqual(self.emby.messages, [])

    def test_message_on_playback_start(self):
        self.cfg.warn_on_start = True
        self.cfg.start_text = "Il te reste {remaining} sur ton quota {scope}."
        self.emby.add_session("s1", "u-kid", "Enfant1", item="Le Grand Bleu")
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        session_id, message = self.emby.messages[0]
        self.assertEqual(session_id, "s1")
        self.assertEqual(message["Header"], self.cfg.start_header)
        self.assertIn("10m00", message["Text"])
        self.assertIn("jour", message["Text"])
        # pas de repetition tant que le meme titre est lu
        self.tick(20)
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)

    def test_new_message_on_the_next_title(self):
        self.cfg.warn_on_start = True
        session = self.emby.add_session("s1", "u-kid", "Enfant1", item="Episode 1")
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        session["NowPlayingItem"] = {"Id": "item-2", "Name": "Episode 2"}
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 2)

    def test_start_message_is_resent_after_the_session_disappears(self):
        self.cfg.warn_on_start = True
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.emby.sessions.clear()
        self.tick(20)
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 2)

    def scope_warned(self, scope: str = "daily") -> set:
        key = eq.scope_key(datetime.fromtimestamp(self.clock()), scope, self.cfg)
        return self.store.get_usage("u-kid", key).warned_tokens()

    def seed(self, seconds: float, scope: str = "daily") -> None:
        """Positionne le compteur sans passer par des dizaines de cycles."""
        key = eq.scope_key(datetime.fromtimestamp(self.clock()), scope, self.cfg)
        row = self.store.get_usage("u-kid", key)
        row.user_name = "Enfant1"
        row.seconds = seconds
        self.store.save_usage(row)

    def test_percent_threshold(self):
        self.cfg.warn_at_percent = [80]
        self.cfg.warn_text = "Tu as consomme {percent} % de ton quota {scope}."
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed(60 * 7)  # 70 % de 10 min
        self.tick()
        self.assertEqual(self.emby.messages, [])
        self.seed(60 * 8 - 20)  # le cycle suivant ajoute 20 s -> pile 80 %
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)
        # le message annonce la consommation reelle, pas le palier
        self.assertIn("80 %", self.emby.messages[0][1]["Text"])
        self.assertIn("jour", self.emby.messages[0][1]["Text"])
        self.assertEqual(self.scope_warned(), {"p80"})
        self.seed(60 * 9)  # 90 % : pas de second message pour le meme palier
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)

    def test_several_percent_thresholds_do_not_spam(self):
        """Demarrage tardif : 50 et 80 franchis d'un coup -> un seul message."""
        self.cfg.warn_at_percent = [50, 80, 95]
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed(60 * 9)  # 90 %
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.assertEqual(self.scope_warned(), {"p50", "p80"})
        self.seed(60 * 9.6)  # 96 % -> nouveau palier
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 2)

    def test_minute_threshold_wider_than_the_quota_is_ignored(self):
        """Palier a 5 min sur un quota de 3 min : il partirait des la 1re seconde."""
        self.cfg.daily_minutes = 3
        self.cfg.warn_at_minutes = [5]
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        self.assertEqual(self.emby.messages, [])
        self.assertEqual(self.scope_warned(), set())
        self.assertNotIn("palier 5 min", self.monitor._next_step(
            self.store.get_usage(
                "u-kid",
                eq.scope_key(datetime.fromtimestamp(self.clock()), "daily", self.cfg),
            ),
            160.0,
            self.clock(),
        ))

    def test_minute_threshold_narrower_than_the_quota_still_fires(self):
        self.cfg.daily_minutes = 10
        self.cfg.warn_at_minutes = [5]
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed(60 * 5)
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)

    def test_percent_and_minutes_coexist(self):
        self.cfg.warn_at_percent = [50]
        self.cfg.warn_at_minutes = [1]
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed(60 * 5)   # 50 %
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.seed(60 * 9)   # reste 1 min
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 2)
        self.assertEqual(self.scope_warned(), {"p50", "m1"})

    def test_percent_scope_binding(self):
        """warn_percent_scope = binding : sur la periode qui contraint."""
        self.cfg.daily_minutes = 20
        self.cfg.weekly_minutes = 12  # la semaine est plus serree en proportion
        self.cfg.warn_percent_scope = "binding"
        self.cfg.warn_at_percent = [80]
        self.cfg.warn_text = "%periode% : %pourcentage% %"
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed(600, "daily")    # 50 % du jour
        self.seed(600, "weekly")   # 83 % de la semaine
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.assertIn("semaine : 83 %", self.emby.messages[0][1]["Text"])
        self.assertEqual(self.scope_warned("weekly"), {"p80"})
        self.assertEqual(self.scope_warned("daily"), set())

    def test_bonus_reopens_the_thresholds(self):
        self.cfg.warn_at_percent = [80]
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed(60 * 8)
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        eq.grant_bonus(self.cfg, self.store, "u-kid", "Enfant1", 10, now=self.now())
        self.assertEqual(self.scope_warned(), set())
        self.seed(60 * 16)  # 16 min sur 20 = 80 % du nouveau quota
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 2)

    def test_default_templates_render_cleanly(self):
        """Les textes livres par defaut ne doivent pas produire de '9s minute(s)'."""
        cfg = make_config()
        row = eq.UsageRow(
            user_id="u", period_key="k", user_name="Enfant1", seconds=3591
        )
        fin = datetime(2026, 9, 7, 4, 0)
        for gabarit in (cfg.start_text, cfg.warn_text, cfg.stop_text):
            texte = self.monitor._format(gabarit, row, "daily", 9.0, 3600.0, fin)
            self.assertNotIn("{", texte)
            self.assertNotIn("minute(s)", texte)
        self.assertEqual(
            self.monitor._format(cfg.warn_text, row, "daily", 9.0, 3600.0, fin),
            "Il te reste 9s de visionnage pour la journee (100 % consomme).",
        )
        self.assertEqual(
            self.monitor._format(cfg.stop_text, row, "weekly", 0.0, 3600.0, fin),
            "Quota de la semaine atteint (59m51 vues). "
            "Le film va s'arreter dans 0s.",
        )

    def test_template_variables(self):
        row = eq.UsageRow(user_id="u", period_key="k", user_name="Enfant1", seconds=1800)
        text = self.monitor._format(
            "{user} {used} {remaining} {remaining_min} {quota} {quota_min} "
            "{percent} {scope} {reset_time}",
            row, "weekly", 1800.0, 3600.0, datetime(2026, 9, 7, 4, 0),
        )
        self.assertEqual(text, "Enfant1 30m00 30m00 30 1h00 60 50 semaine 04:00")


class TestRenderTemplate(unittest.TestCase):
    VARS = {
        "user": "Enfant1",
        "remaining_daily": "45m00",
        "remaining_monthly": "11h00",
        "percent": 62,
    }

    def test_percent_syntax(self):
        self.assertEqual(
            eq.render_template("Bonjour %user%", self.VARS), "Bonjour Enfant1"
        )

    def test_french_aliases(self):
        self.assertEqual(
            eq.render_template(
                "Bonjour %pseudo% il vous reste %tempsrestant_jour% pour "
                "aujourd'hui et %tempsrestant_mois% pour le mois.",
                self.VARS,
            ),
            "Bonjour Enfant1 il vous reste 45m00 pour aujourd'hui et 11h00 "
            "pour le mois.",
        )

    def test_brace_syntax_still_works(self):
        self.assertEqual(
            eq.render_template("{pseudo} : {tempsrestant_jour}", self.VARS),
            "Enfant1 : 45m00",
        )

    def test_mixed_syntaxes(self):
        self.assertEqual(
            eq.render_template("%pseudo% / {remaining_daily}", self.VARS),
            "Enfant1 / 45m00",
        )

    def test_unknown_variable_is_left_alone(self):
        self.assertEqual(
            eq.render_template("%inconnu% et {autre}", self.VARS),
            "%inconnu% et {autre}",
        )

    def test_case_insensitive(self):
        self.assertEqual(eq.render_template("%PSEUDO%", self.VARS), "Enfant1")

    def test_bare_percent_sign_is_preserved(self):
        self.assertEqual(
            eq.render_template("%percent% % consomme", self.VARS), "62 % consomme"
        )

    def test_empty_and_none(self):
        self.assertEqual(eq.render_template("", self.VARS), "")
        self.assertEqual(eq.render_template(None, self.VARS), "")

    def test_numbers_are_stringified(self):
        self.assertEqual(eq.render_template("%percent%", self.VARS), "62")


class TestShownScopes(BaseCase):
    config_overrides = {
        "daily_minutes": 60,
        "weekly_minutes": 300,
        "monthly_minutes": 1200,
        "warn_on_login": True,
        "warn_at_minutes": [],
        "warn_at_percent": [],
    }

    def greet(self) -> str:
        self.tick()  # amorcage
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        return self.emby.messages[0][1]["Text"]

    def test_all_scopes_shown_by_default(self):
        texte = self.greet()
        for mot in ("le mois", "la semaine", "la journee"):
            self.assertIn(mot, texte)

    def test_unchecking_a_scope_removes_it_from_the_summary(self):
        self.cfg.show_monthly = False
        texte = self.greet()
        self.assertNotIn("le mois", texte)
        self.assertIn("la semaine", texte)
        self.assertIn("la journee", texte)

    def test_unchecked_scope_is_still_enforced(self):
        """Decocher l'affichage ne desactive pas le quota."""
        self.cfg.show_daily = False
        self.cfg.daily_minutes = 1
        self.cfg.grace_seconds = 0
        self.tick()  # amorcage
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick(20)  # premiere observation, non facturee
        for _ in range(3):
            self.tick(20)  # 60 s = quota
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])

    def test_individual_variables_ignore_the_checkboxes(self):
        self.cfg.show_monthly = False
        self.cfg.login_text = "mois %tempsrestant_mois%"
        self.assertEqual(self.greet(), "mois 20h00")

    def test_shown_scopes_property(self):
        self.assertEqual(self.cfg.shown_scopes, ["daily", "weekly", "monthly"])
        self.cfg.show_weekly = False
        self.assertEqual(self.cfg.shown_scopes, ["daily", "monthly"])


class TestPreviewMessage(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = make_config(
            daily_minutes=60, weekly_minutes=300, monthly_minutes=1200
        )

    def test_every_kind_renders(self):
        for kind, *_ in eq.MESSAGE_KINDS:
            header, text = eq.preview_message(self.cfg, kind)
            self.assertTrue(text)
            self.assertNotIn("%", text.replace(" % ", ""))
            self.assertNotIn("{", text)

    def test_unknown_kind_raises(self):
        with self.assertRaises(ValueError):
            eq.preview_message(self.cfg, "inconnu")

    def test_preview_uses_the_configured_template(self):
        self.cfg.login_text = "Salut %pseudo%, %tempsrestant_jour% aujourd'hui"
        _, text = eq.preview_message(self.cfg, "login")
        self.assertEqual(text, "Salut Enfant1, 45m00 aujourd'hui")

    def test_preview_honours_the_checkboxes(self):
        self.cfg.login_text = "%resume%"
        self.cfg.show_monthly = False
        _, text = eq.preview_message(self.cfg, "login")
        self.assertNotIn("le mois", text)
        self.cfg.show_monthly = True
        _, text = eq.preview_message(self.cfg, "login")
        self.assertIn("le mois", text)

    def test_preview_of_an_unlimited_scope(self):
        cfg = make_config(daily_minutes=60, monthly_minutes=0)
        cfg.login_text = "%tempsrestant_mois%"
        self.assertEqual(eq.preview_message(cfg, "login")[1], "illimite")

    def test_preview_survives_a_broken_template(self):
        self.cfg.warn_text = "reste %nimportequoi% !"
        self.assertEqual(
            eq.preview_message(self.cfg, "warn")[1], "reste %nimportequoi% !"
        )


class TestMessageVariablesLive(BaseCase):
    config_overrides = {
        "daily_minutes": 60,
        "weekly_minutes": 300,
        "warn_on_start": True,
        "warn_at_minutes": [],
        "warn_at_percent": [],
    }

    def test_title_client_and_device_in_a_real_message(self):
        self.cfg.start_text = "%titre% sur %client%/%appareil% - reste %tempsrestant%"
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", item="Le Grand Bleu",
            client="Emby Android", device="Pixel",
        )
        self.tick()
        self.assertEqual(
            self.emby.messages[0][1]["Text"],
            "Le Grand Bleu sur Emby Android/Pixel - reste 1h00",
        )

    def test_all_scope_variables_available_in_any_message(self):
        self.cfg.start_text = "%tempsrestant_jour% / %tempsrestant_semaine%"
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.assertEqual(self.emby.messages[0][1]["Text"], "1h00 / 5h00")

    def test_header_is_also_a_template(self):
        self.cfg.start_header = "%bonjour% %pseudo%"
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.assertEqual(self.emby.messages[0][1]["Header"], "Bonjour Enfant1")

    def test_ini_round_trip_of_a_french_template(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False, encoding="utf-8"
        )
        handle.write(
            "[server]\napi_key = k\n[enforcement]\n"
            "show_monthly = false\n"
            "login_text = Bonjour %pseudo% il vous reste %tempsrestant_jour% "
            "pour aujourd'hui et %tempsrestant_mois% pour le mois.\n"
        )
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        cfg = eq.load_config(handle.name)
        self.assertFalse(cfg.show_monthly)
        self.assertIn("%pseudo%", cfg.login_text)
        self.assertIn("%tempsrestant_jour%", cfg.login_text)


class TestServerSettings(unittest.TestCase):
    """URL, cle API et timeout doivent etre modifiables depuis une interface."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ini = os.path.join(self.tmp, "emby_quota.ini")

    def test_api_key_required_by_default(self):
        with open(self.ini, "w", encoding="utf-8") as handle:
            handle.write("[server]\nurl = http://nas:8096\n")
        with self.assertRaises(ValueError):
            eq.load_config(self.ini)

    def test_api_key_optional_for_the_interfaces(self):
        with open(self.ini, "w", encoding="utf-8") as handle:
            handle.write("[server]\nurl = http://nas:8096\n")
        cfg = eq.load_config(self.ini, require_api_key=False)
        self.assertEqual(cfg.api_key, "")
        self.assertEqual(cfg.url, "http://nas:8096")

    def test_update_ini_creates_a_missing_file(self):
        chemin = os.path.join(self.tmp, "neuf.ini")
        eq.update_ini(
            chemin,
            {"server": {"url": "http://nas:8096", "api_key": "abc"}},
        )
        cfg = eq.load_config(chemin)
        self.assertEqual(cfg.url, "http://nas:8096")
        self.assertEqual(cfg.api_key, "abc")

    def test_server_settings_round_trip(self):
        with open(self.ini, "w", encoding="utf-8") as handle:
            handle.write(
                "; mon fichier\n[server]\nurl = http://ancien:8096\n"
                "api_key = ancienne\ntimeout = 10\n"
            )
        eq.update_ini(
            self.ini,
            {
                "server": {
                    "url": "http://192.168.1.10:8096",
                    "api_key": "nouvelle",
                    "timeout": "20",
                }
            },
        )
        cfg = eq.load_config(self.ini)
        self.assertEqual(cfg.url, "http://192.168.1.10:8096")
        self.assertEqual(cfg.api_key, "nouvelle")
        self.assertEqual(cfg.http_timeout, 20)
        with open(self.ini, encoding="utf-8") as handle:
            self.assertIn("; mon fichier", handle.read())

    def test_reload_config_reconnects_the_api(self):
        emby_a = MockEmby(api_key="cle-a").start()
        emby_b = MockEmby(api_key="cle-b").start()
        self.addCleanup(emby_a.stop)
        self.addCleanup(emby_b.stop)
        emby_a.add_user("u1", "A")
        emby_b.add_user("u2", "B")
        emby_b.add_user("u3", "C")

        cfg = make_config(url=emby_a.url, api_key="cle-a")
        store = eq.Store(":memory:")
        self.addCleanup(store.close)
        monitor = eq.Monitor(cfg, eq.EmbyApi(cfg.url, cfg.api_key), store)
        self.assertEqual(len(monitor.api.users()), 1)

        # on bascule vers un autre serveur, avec une autre cle
        nouvelle = make_config(url=emby_b.url, api_key="cle-b", http_timeout=5)
        monitor.reload_config(nouvelle)
        self.assertEqual(len(monitor.api.users()), 2)
        self.assertEqual(monitor.api.timeout, 5)
        self.assertEqual(monitor._users_cache, {})

    def test_wrong_key_after_reload_is_reported(self):
        emby = MockEmby(api_key="bonne").start()
        self.addCleanup(emby.stop)
        cfg = make_config(url=emby.url, api_key="bonne")
        store = eq.Store(":memory:")
        self.addCleanup(store.close)
        monitor = eq.Monitor(cfg, eq.EmbyApi(cfg.url, cfg.api_key), store)
        monitor.reload_config(make_config(url=emby.url, api_key="mauvaise"))
        with self.assertRaises(eq.EmbyError):
            monitor.api.sessions()


class TestDefaultsAreStrict(unittest.TestCase):
    """Rien n'est dispense de quota tant que l'exploitant ne l'a pas demande."""

    def test_no_exemption_out_of_the_box(self):
        cfg = eq.Config(api_key="k")
        self.assertFalse(hasattr(cfg, "exempt_admins"))  # le concept n'existe plus
        self.assertEqual(cfg.exempt_users, [])
        self.assertEqual(cfg.exempt_networks, [])
        self.assertEqual(cfg.escalation, "none")

    def test_no_automatic_exemption_exists_at_all(self):
        """Aucun role, aucun statut ne dispense : seule la liste nominative."""
        self.assertNotIn("exempt_admins", eq.Config.__dataclass_fields__)
        self.assertNotIn("IsAdministrator", open(
            eq.__file__,
            encoding="utf-8",
        ).read())

    def test_obsolete_key_is_ignored_with_a_warning(self):
        """Un ancien fichier avec exempt_admins = true ne doit exempter personne."""
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False, encoding="utf-8"
        )
        handle.write("[server]\napi_key = k\n[quota]\nexempt_admins = true\n")
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        with self.assertLogs(eq.LOG, level=logging.WARNING) as captured:
            cfg = eq.load_config(handle.name)
        self.assertIn("exempt_admins", "\n".join(captured.output))
        self.assertEqual(cfg.exempt_users, [])

    def test_shipped_example_exempts_nobody(self):
        example = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "emby_quota.ini.example")
        cfg = eq.load_config(example)
        self.assertEqual(cfg.exempt_users, [])
        self.assertEqual(cfg.exempt_networks, [])


class TestLanIsNotExempt(BaseCase):
    """Le LAN de la maison est justement la ou regardent les enfants."""

    config_overrides = {
        "daily_minutes": 1,
        "warn_at_minutes": [],
        "grace_seconds": 0,
    }

    def test_lan_session_is_counted_and_stopped(self):
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", endpoint="192.168.1.42:5000"
        )
        self.tick()
        self.tick(20)
        key = eq.scope_key(datetime.fromtimestamp(self.clock()), "daily", self.cfg)
        self.assertAlmostEqual(self.store.get_usage("u-kid", key).seconds, 20.0)
        self.tick(20)
        self.tick(20)
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])

    def test_admin_is_counted(self):
        self.emby.add_session("s1", "u-adm", "Alice", endpoint="192.168.1.10:5000")
        self.tick()
        self.tick(20)
        key = eq.scope_key(datetime.fromtimestamp(self.clock()), "daily", self.cfg)
        self.assertAlmostEqual(self.store.get_usage("u-adm", key).seconds, 20.0)

    def test_exemption_is_opt_in_and_works(self):
        self.monitor.reload_config(
            make_config(url=self.emby.url, daily_minutes=1,
                        exempt_networks=["192.168.1.0/24"])
        )
        self.emby.add_session("s1", "u-kid", "Enfant1", endpoint="192.168.1.42:5000")
        self.tick()
        self.tick(20)
        key = eq.scope_key(datetime.fromtimestamp(self.clock()), "daily", self.cfg)
        self.assertEqual(self.store.get_usage("u-kid", key).seconds, 0.0)


class TestMessageTimeouts(BaseCase):
    config_overrides = {
        "daily_minutes": 1,
        "warn_on_login": True,
        "warn_on_start": True,
        "warn_at_minutes": [],
        "warn_at_percent": [],
        "grace_seconds": 0,
        "message_timeout_seconds": 8,
        "login_timeout_seconds": 15,
        "stop_timeout_seconds": 20,
    }

    def test_config_resolves_per_kind(self):
        cfg = self.cfg
        self.assertEqual(cfg.timeout_seconds("login"), 15)
        self.assertEqual(cfg.timeout_seconds("stop"), 20)
        self.assertEqual(cfg.timeout_seconds("start"), 8)   # suit le global
        self.assertEqual(cfg.timeout_seconds("warn"), 8)
        self.assertEqual(cfg.timeout_seconds(""), 8)
        # l'API Emby veut des millisecondes
        self.assertEqual(cfg.timeout_ms("login"), 15000)
        self.assertEqual(cfg.timeout_ms("start"), 8000)

    def test_default_is_eight_seconds(self):
        cfg = make_config()
        self.assertEqual(cfg.timeout_seconds(), 8)
        self.assertEqual(cfg.timeout_ms("warn"), 8000)

    def test_legacy_milliseconds_still_work(self):
        cfg = make_config(message_timeout_ms=5000, login_timeout_ms=12000)
        self.assertEqual(cfg.timeout_seconds("login"), 12)
        self.assertEqual(cfg.timeout_seconds("warn"), 5)

    def test_seconds_win_over_milliseconds(self):
        cfg = make_config(login_timeout_seconds=3, login_timeout_ms=99000)
        self.assertEqual(cfg.timeout_ms("login"), 3000)

    def test_global_seconds_apply_to_every_kind(self):
        cfg = make_config(message_timeout_seconds=12)
        for kind in ("login", "start", "warn", "stop"):
            self.assertEqual(cfg.timeout_seconds(kind), 12, msg=kind)

    def test_each_message_uses_its_own_timeout(self):
        self.tick()  # amorcage
        self.emby.add_session("s1", "u-kid", "Enfant1", item="Le Grand Bleu")
        self.tick(20)
        self.assertEqual(self.emby.messages[0][1]["TimeoutMs"], 15000)  # connexion
        self.emby.sessions[0]["NowPlayingItem"] = {"Id": "i2", "Name": "Suite"}
        self.tick(20)
        self.assertEqual(self.emby.messages[1][1]["TimeoutMs"], 8000)   # debut
        self.tick(20)
        self.tick(20)
        # le dernier message est celui de la coupure effective
        self.assertEqual(
            self.emby.messages[-1][1]["TimeoutMs"],
            self.cfg.timeout_seconds("stopped") * 1000,
        )
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])

    def test_zero_omits_the_field_for_a_persistent_message(self):
        """Emby : sans TimeoutMs, le message reste affiche jusqu'a fermeture."""
        self.cfg.login_timeout_seconds = 0
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        envoye = self.emby.messages[0][1]
        self.assertNotIn("TimeoutMs", envoye)
        self.assertIn("Text", envoye)

    def test_negative_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            make_config(stop_timeout_seconds=-1).validate()
        with self.assertRaises(ValueError):
            make_config(stop_timeout_ms=-1).validate()

    def test_tooshort_has_its_own_duration(self):
        cfg = make_config(tooshort_timeout_seconds=25)
        self.assertEqual(cfg.timeout_seconds("tooshort"), 25)
        self.assertEqual(cfg.timeout_seconds("start"), 8)

    def test_tooshort_message_uses_its_duration(self):
        self.cfg.warn_if_too_short = True
        self.cfg.warn_on_login = False   # sinon l'accueil consomme l'annonce
        self.cfg.tooshort_timeout_seconds = 25
        self.tick()
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", runtime_seconds=9999
        )
        self.tick(20)
        envoye = [m for _, m in self.emby.messages if m["Header"] == "Attention"]
        self.assertEqual(envoye[0]["TimeoutMs"], 25000)

    def test_command_route(self):
        """L'autre route de l'API, pour les clients qui la traitent mieux."""
        self.cfg.message_route = "command"
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(len(self.emby.commands), 1)
        session_id, nom, arguments = self.emby.commands[0]
        self.assertEqual(session_id, "s1")
        self.assertEqual(nom, "DisplayMessage")
        self.assertEqual(arguments["TimeoutMs"], 15000)
        self.assertIn("Header", arguments)

    def test_invalid_route_is_rejected(self):
        with self.assertRaises(ValueError):
            make_config(message_route="popup").validate()

    def test_repeat_count_sends_the_message_several_times(self):
        """Compense les clients qui n'appliquent pas la duree demandee."""
        self.cfg.login_repeat_count = 3
        self.cfg.message_repeat_interval_seconds = 3
        self.tick()  # amorcage
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        # le premier part tout de suite, les deux autres sont programmes
        self.assertEqual(len(self.emby.messages), 1)
        self.assertEqual(len(self.monitor._pending_messages), 2)

        self.clock.advance(3)
        self.assertEqual(self.monitor.flush_pending_messages(), 1)
        self.assertEqual(len(self.emby.messages), 2)
        self.clock.advance(3)
        self.assertEqual(self.monitor.flush_pending_messages(), 1)
        self.assertEqual(len(self.emby.messages), 3)
        # et on s'arrete la
        self.clock.advance(30)
        self.assertEqual(self.monitor.flush_pending_messages(), 0)
        self.assertEqual(len(self.emby.messages), 3)

    def test_repetitions_are_identical_and_keep_their_duration(self):
        self.cfg.login_repeat_count = 2
        self.cfg.login_timeout_seconds = 15
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.clock.advance(5)
        self.monitor.flush_pending_messages()
        premier, second = self.emby.messages[0][1], self.emby.messages[1][1]
        self.assertEqual(premier["Text"], second["Text"])
        self.assertEqual(premier["Header"], second["Header"])
        self.assertEqual(second["TimeoutMs"], 15000)

    def test_known_client_caps(self):
        """Durees codees en dur relevees par la communaute Emby."""
        self.assertEqual(eq.known_display_cap("Emby for Roku"), 6)
        self.assertEqual(eq.known_display_cap("Emby Android TV"), 5)
        self.assertEqual(eq.known_display_cap("Nvidia Shield"), 5)
        self.assertIsNone(eq.known_display_cap("Emby Web"))
        self.assertIsNone(eq.known_display_cap(""))
        self.assertIsNone(eq.known_display_cap(None))

    def test_repeats_for_duration(self):
        self.assertEqual(eq.repeats_for_duration(15, 5), 3)
        self.assertEqual(eq.repeats_for_duration(30, 5), 6)
        self.assertEqual(eq.repeats_for_duration(20, 6), 4)
        # une cible plus courte que l'intervalle tient en un seul affichage
        self.assertEqual(eq.repeats_for_duration(3, 5), 1)
        self.assertEqual(eq.repeats_for_duration(5, 5), 1)
        # jamais de division par zero
        self.assertEqual(eq.repeats_for_duration(30, 0), 1)

    def test_repeat_count_actually_covers_the_target(self):
        """Le calcul doit tenir : N affichages a I secondes couvrent la cible."""
        for cible, intervalle in ((15, 5), (30, 5), (20, 6), (60, 4)):
            nombre = eq.repeats_for_duration(cible, intervalle)
            self.assertGreaterEqual(nombre * intervalle, cible)

    def test_count_per_kind(self):
        cfg = make_config(message_repeat_count=2, stop_repeat_count=5)
        self.assertEqual(cfg.repeat_count("stop"), 5)
        self.assertEqual(cfg.repeat_count("warn"), 2)   # suit le global
        self.assertEqual(cfg.repeat_count(""), 2)
        self.assertEqual(make_config().repeat_count("login"), 1)

    def test_count_below_one_is_rejected(self):
        with self.assertRaises(ValueError):
            make_config(warn_repeat_count=0).validate()
        with self.assertRaises(ValueError):
            make_config(message_repeat_interval_seconds=0).validate()

    def test_repeat_disabled_by_default(self):
        self.assertEqual(eq.Config(api_key="k").message_repeat_count, 1)
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(self.monitor._pending_messages, [])
        self.clock.advance(60)
        self.monitor.flush_pending_messages()
        self.assertEqual(len(self.emby.messages), 1)

    def test_pending_repetitions_dropped_when_playback_is_stopped(self):
        """Inutile de repeter un avertissement apres avoir coupe le film."""
        self.cfg.warn_on_login = False
        self.cfg.stopped_repeat_count = 3
        self.cfg.daily_minutes = 1
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        for _ in range(3):
            self.tick(20)
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])
        self.assertEqual(self.monitor._pending_messages, [])

    def test_ini_parsing_of_repeat_counts(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False, encoding="utf-8"
        )
        handle.write(
            "[server]\napi_key = k\n[enforcement]\n"
            "message_repeat_count = 2\nstopped_repeat_count = 4\n"
            "message_repeat_interval_seconds = 2.5\n"
        )
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        cfg = eq.load_config(handle.name)
        self.assertEqual(cfg.repeat_count("stopped"), 4)
        self.assertEqual(cfg.repeat_count("warn"), 2)
        self.assertEqual(cfg.message_repeat_interval_seconds, 2.5)

    def test_ini_parsing_in_seconds(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False, encoding="utf-8"
        )
        handle.write(
            "[server]\napi_key = k\n"
            "[enforcement]\nmessage_timeout_seconds = 5\n"
            "login_timeout_seconds = 12\n"
        )
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        cfg = eq.load_config(handle.name)
        self.assertEqual(cfg.timeout_seconds("login"), 12)
        self.assertEqual(cfg.timeout_seconds("warn"), 5)
        self.assertEqual(cfg.timeout_ms("login"), 12000)

    def test_ini_parsing_legacy_milliseconds(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False, encoding="utf-8"
        )
        handle.write(
            "[server]\napi_key = k\n"
            "[enforcement]\nmessage_timeout_ms = 5000\nlogin_timeout_ms = 12000\n"
        )
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        cfg = eq.load_config(handle.name)
        self.assertEqual(cfg.timeout_ms("login"), 12000)
        self.assertEqual(cfg.timeout_ms("warn"), 5000)
        self.assertEqual(cfg.timeout_seconds("login"), 12)


class TestLoginGreeting(BaseCase):
    """Recapitulatif envoye a la connexion d'un client."""

    config_overrides = {
        "daily_minutes": 60,
        "weekly_minutes": 300,
        "monthly_minutes": 1200,
        "warn_on_login": True,
        "warn_on_start": False,
        "warn_at_minutes": [],
        "warn_at_percent": [],
    }

    def seed(self, scope: str, seconds: float, user_id: str = "u-kid") -> None:
        key = eq.scope_key(datetime.fromtimestamp(self.clock()), scope, self.cfg)
        row = self.store.get_usage(user_id, key)
        row.user_name = "Enfant1"
        row.seconds = seconds
        self.store.save_usage(row)

    def test_sessions_already_open_are_greeted_at_startup(self):
        """Emby garde les sessions listees : sans cela, personne ne serait salue."""
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)

    def test_startup_greeting_can_be_disabled(self):
        self.cfg.greet_at_startup = False
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.assertEqual(self.emby.messages, [])

    def iso(self, decalage: float = 0.0) -> str:
        """Horodatage Emby, cale sur l'horloge injectee."""
        return (
            datetime.fromtimestamp(self.clock() + decalage).isoformat() + ".0000000Z"
        )

    def test_parse_emby_date(self):
        # Emby met 7 decimales, datetime n'en accepte que 6
        self.assertIsNotNone(eq.Monitor.parse_emby_date("2026-09-06T21:00:00.1234567Z"))
        self.assertIsNotNone(eq.Monitor.parse_emby_date("2026-09-06T21:00:00Z"))
        self.assertIsNotNone(eq.Monitor.parse_emby_date("2026-09-06T21:00:00"))
        self.assertIsNone(eq.Monitor.parse_emby_date(""))
        self.assertIsNone(eq.Monitor.parse_emby_date(None))
        self.assertIsNone(eq.Monitor.parse_emby_date("pas une date"))
        a = eq.Monitor.parse_emby_date("2026-09-06T21:00:00Z")
        b = eq.Monitor.parse_emby_date("2026-09-06T21:05:00Z")
        self.assertAlmostEqual(b - a, 300)

    def test_reconnection_on_an_existing_session(self):
        """Emby garde la session listee : c'est le reveil qui signale le retour."""
        session = self.emby.add_session(
            "s1", "u-kid", "Enfant1", item=None, last_activity=self.iso()
        )
        self.tick()                       # salue au demarrage
        self.assertEqual(len(self.emby.messages), 1)
        self.cfg.login_cooldown_minutes = 0   # on isole le mecanisme de reveil

        # la session dort 20 minutes : l'activite ne bouge pas
        self.tick(20 * 60)
        self.assertEqual(len(self.emby.messages), 1)

        # l'utilisateur rouvre son application : l'activite bondit
        self.clock.advance(20)
        session["LastActivityDate"] = self.iso()
        self.monitor.tick()
        self.assertEqual(len(self.emby.messages), 2)

    def test_short_inactivity_is_not_a_reconnection(self):
        session = self.emby.add_session(
            "s1", "u-kid", "Enfant1", item=None, last_activity=self.iso()
        )
        self.tick()
        self.cfg.login_cooldown_minutes = 0
        # 5 minutes d'inactivite, seuil a 15 : ce n'est pas un retour
        self.clock.advance(5 * 60)
        session["LastActivityDate"] = self.iso()
        self.monitor.tick()
        self.assertEqual(len(self.emby.messages), 1)

    def test_idle_threshold_is_configurable(self):
        self.cfg.login_idle_minutes = 2
        session = self.emby.add_session(
            "s1", "u-kid", "Enfant1", item=None, last_activity=self.iso()
        )
        self.tick()
        self.cfg.login_cooldown_minutes = 0
        self.clock.advance(3 * 60)
        session["LastActivityDate"] = self.iso()
        self.monitor.tick()
        self.assertEqual(len(self.emby.messages), 2)

    def test_activity_that_never_moves_never_triggers(self):
        """Un client qui ne publie pas d'activite ne doit pas spammer."""
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None, last_activity=None)
        self.tick()
        self.cfg.login_cooldown_minutes = 0
        for _ in range(5):
            self.tick(600)
        self.assertEqual(len(self.emby.messages), 1)

    def test_cooldown_is_off_by_default(self):
        """Rien n'a ete demande : l'anti-rebond ne s'impose pas tout seul."""
        self.assertFalse(eq.Config().login_cooldown_enabled)
        self.assertEqual(eq.Config().cooldown_seconds(), 0)

    def test_every_reconnection_is_greeted_when_the_cooldown_is_off(self):
        """Comportement par defaut : chaque connexion detectee dit bonjour."""
        self.tick()
        for numero in range(1, 4):
            self.emby.add_session(f"s{numero}", "u-kid", "Enfant1", item=None)
            self.tick(20)
            self.emby.sessions.clear()
            self.tick(20)
        self.assertEqual(len(self.emby.messages), 3)

    def test_the_checkbox_alone_decides(self):
        """Les minutes ne servent a rien tant que la case n'est pas cochee."""
        self.cfg.login_cooldown_minutes = 60
        self.cfg.login_cooldown_enabled = False
        self.assertEqual(self.cfg.cooldown_seconds(), 0)
        self.cfg.login_cooldown_enabled = True
        self.assertEqual(self.cfg.cooldown_seconds(), 3600)

    def test_cooldown_still_applies_to_reconnections(self):
        self.cfg.login_cooldown_enabled = True
        session = self.emby.add_session(
            "s1", "u-kid", "Enfant1", item=None, last_activity=self.iso()
        )
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        # anti-rebond de 60 min : un reveil 30 min plus tard ne redit rien
        self.clock.advance(30 * 60)
        session["LastActivityDate"] = self.iso()
        self.monitor.tick()
        self.assertEqual(len(self.emby.messages), 1)

    def test_verbose_explains_why_nothing_was_sent(self):
        self.cfg.login_cooldown_enabled = True
        session = self.emby.add_session(
            "s1", "u-kid", "Enfant1", item=None, last_activity=self.iso()
        )
        self.tick()
        self.clock.advance(20 * 60)
        session["LastActivityDate"] = self.iso()
        with self.assertLogs(eq.LOG, level=logging.DEBUG) as captured:
            self.monitor.tick()
        texte = "\n".join(captured.output)
        self.assertIn("anti-rebond", texte)
        self.assertIn("Enfant1", texte)

    def test_message_on_a_new_session(self):
        self.tick()  # amorcage, aucune session
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)
        session_id, message = self.emby.messages[0]
        self.assertEqual(session_id, "s1")
        self.assertEqual(message["Header"], "Temps de visionnage")
        self.assertEqual(
            message["Text"],
            "Bonjour Enfant1, il vous reste 20h00 pour le mois, 5h00 pour la "
            "semaine et 1h00 pour la journee. Bon visionnage.",
        )

    def test_message_reflects_what_is_left(self):
        self.seed("daily", 15 * 60)
        self.seed("weekly", 60 * 60)
        self.seed("monthly", 600 * 60)
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertIn(
            "10h00 pour le mois, 4h00 pour la semaine et 45m00 pour la journee",
            self.emby.messages[0][1]["Text"],
        )

    def test_only_limited_scopes_are_mentioned(self):
        self.cfg.weekly_minutes = None
        self.cfg.monthly_minutes = 0  # suivi mais sans limite
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        texte = self.emby.messages[0][1]["Text"]
        self.assertIn("1h00 pour la journee", texte)
        self.assertNotIn("semaine", texte)
        self.assertNotIn("mois", texte)

    def test_no_message_when_nothing_is_limited(self):
        self.cfg.daily_minutes = 0
        self.cfg.weekly_minutes = 0
        self.cfg.monthly_minutes = 0
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(self.emby.messages, [])

    def test_exempt_user_is_not_greeted(self):
        self.monitor.reload_config(
            make_config(url=self.emby.url, daily_minutes=60, warn_on_login=True,
                        exempt_users=["Alice"])
        )
        self.tick()
        self.emby.add_session("s1", "u-adm", "Alice", item=None)
        self.tick(20)
        self.assertEqual(self.emby.messages, [])

    def test_one_message_even_with_several_devices(self):
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", device="TV", item=None)
        self.emby.add_session("s2", "u-kid", "Enfant1", device="Tablette", item=None)
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)

    def test_cooldown_blocks_a_second_greeting(self):
        self.cfg.login_cooldown_enabled = True
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)
        self.emby.sessions.clear()
        self.tick(20)
        self.emby.add_session("s2", "u-kid", "Enfant1", item=None)
        self.tick(20)   # reconnexion 40 s plus tard : anti-rebond de 60 min
        self.assertEqual(len(self.emby.messages), 1)

    def test_greeting_returns_after_the_cooldown(self):
        self.cfg.login_cooldown_enabled = True
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.emby.sessions.clear()
        self.tick(20)
        self.clock.advance(61 * 60)
        self.monitor.tick()
        self.emby.add_session("s2", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 2)

    def test_cooldown_survives_a_restart(self):
        """L'anti-rebond est en base, pas en memoire."""
        self.cfg.login_cooldown_enabled = True
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)
        # nouveau moniteur, meme base : le service vient de redemarrer
        neuf = eq.Monitor(self.cfg, self.api, self.store, clock=self.clock)
        neuf.tick()                       # amorcage
        self.emby.sessions.clear()
        neuf.tick()
        self.emby.add_session("s2", "u-kid", "Enfant1", item=None)
        self.clock.advance(20)
        neuf.tick()
        self.assertEqual(len(self.emby.messages), 1)

    def test_evening_greeting(self):
        self.clock.advance(8 * 3600)  # 20:00
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertTrue(self.emby.messages[0][1]["Text"].startswith("Bonsoir Enfant1"))

    def test_disabled_by_default(self):
        self.cfg.warn_on_login = False
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(self.emby.messages, [])

    def test_no_duplicate_with_the_start_message(self):
        """Connexion + lecture immediate : un seul message, pas deux."""
        self.cfg.warn_on_start = True
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item="Le Grand Bleu")
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)
        self.assertEqual(self.emby.messages[0][1]["Header"], "Temps de visionnage")
        # le titre suivant declenche bien le message de debut de lecture
        self.emby.sessions[0]["NowPlayingItem"] = {"Id": "item-2", "Name": "Suite"}
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 2)
        self.assertEqual(self.emby.messages[1][1]["Header"], "Bon film")

    def test_custom_template_variables(self):
        self.cfg.login_header = "{greeting} {user}"
        self.cfg.login_text = (
            "{user} sur {client}/{device} : jour {remaining_daily}, "
            "semaine {remaining_weekly}, mois {remaining_monthly}"
        )
        self.tick()
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", item=None, client="Emby Android", device="Pixel"
        )
        self.tick(20)
        header, texte = (
            self.emby.messages[0][1]["Header"],
            self.emby.messages[0][1]["Text"],
        )
        self.assertEqual(header, "Bonjour Enfant1")
        self.assertEqual(
            texte,
            "Enfant1 sur Emby Android/Pixel : jour 1h00, semaine 5h00, mois 20h00",
        )

    def test_unlimited_scope_shows_as_illimite_in_variables(self):
        self.cfg.monthly_minutes = 0
        self.cfg.login_text = "{remaining_monthly}"
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(self.emby.messages[0][1]["Text"], "illimite")

    def test_summary_phrase_joins_correctly(self):
        self.assertEqual(
            eq.Monitor.summary_phrase({"daily": 3600, "weekly": None, "monthly": None}),
            "1h00 pour la journee",
        )
        self.assertEqual(
            eq.Monitor.summary_phrase({"daily": 3600, "weekly": 7200, "monthly": None}),
            "2h00 pour la semaine et 1h00 pour la journee",
        )
        self.assertEqual(eq.Monitor.summary_phrase({}), "")

    def test_login_event_is_journalled(self):
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        events = self.store.events(limit=5)
        self.assertEqual(events[0]["kind"], "login")
        self.assertIn("pour la journee", events[0]["detail"])

    def test_cooldown_is_explained_at_info_level(self):
        """Sans -v non plus, on doit comprendre pourquoi rien ne s'affiche."""
        self.cfg.login_cooldown_enabled = True
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.emby.sessions.clear()
        self.tick(20)
        self.emby.add_session("s2", "u-kid", "Enfant1", item=None)
        with self.assertLogs(eq.LOG, level=logging.INFO) as captured:
            self.tick(20)
        texte = "\n".join(captured.output)
        self.assertIn("anti-rebond", texte)
        self.assertIn("prochain possible dans", texte)
        self.assertIn("--greet", texte)


class TestForcedGreeting(BaseCase):
    """--greet : verifier l'affichage sans attendre l'anti-rebond."""

    config_overrides = {
        "daily_minutes": 60,
        "weekly_minutes": 300,
        "monthly_minutes": 1200,
        "warn_on_login": True,
        "warn_on_start": False,
        "warn_at_minutes": [],
        "warn_at_percent": [],
    }

    def test_greet_now_sends_even_inside_the_cooldown(self):
        self.cfg.login_cooldown_enabled = True
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.tick(20)                       # anti-rebond actif : rien de plus
        self.assertEqual(len(self.emby.messages), 1)
        envoyes = self.monitor.greet_now()
        self.assertEqual(len(self.emby.messages), 2)
        self.assertEqual(len(envoyes), 1)
        self.assertEqual(envoyes[0][0], "Enfant1")
        self.assertIn("pour la journee", envoyes[0][3])

    def test_forced_greeting_does_not_arm_the_cooldown(self):
        """Sinon le test bloquerait le vrai message d'accueil pendant 1 h."""
        self.cfg.login_cooldown_enabled = True
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.monitor.greet_now()
        self.assertEqual(len(self.emby.messages), 1)
        self.assertIsNone(self.store.last_event_ts("u-kid", "login"))
        self.tick(20)                       # connexion normale : message quand meme
        self.assertEqual(len(self.emby.messages), 2)

    def test_greet_now_can_target_one_user(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.emby.add_session("s2", "u-adm", "Alice", item=None)
        envoyes = self.monitor.greet_now("Enfant1")
        self.assertEqual([nom for nom, _app, _sid, _r in envoyes], ["Enfant1"])
        self.assertEqual([sid for sid, _msg in self.emby.messages], ["s1"])

    def test_greet_now_skips_an_exempt_user(self):
        self.cfg.exempt_users = ["Enfant1"]
        self.monitor = eq.Monitor(self.cfg, self.api, self.store, clock=self.clock)
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        envoyes = self.monitor.greet_now()
        self.assertEqual(self.emby.messages, [])
        self.assertEqual(envoyes[0][3], "")

    def test_greet_now_without_session_returns_nothing(self):
        self.assertEqual(self.monitor.greet_now(), [])

    def test_greet_now_reports_the_device(self):
        """Un id de session hexadecimal ne dit pas quel client on a teste."""
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", item=None,
            client="Emby for iOS", device="iPhone de Alice",
        )
        envoyes = self.monitor.greet_now()
        self.assertEqual(envoyes[0][1], "Emby for iOS / iPhone de Alice")


class TestTooShort(BaseCase):
    """Prevenir que le titre lance ne tiendra pas dans le quota restant."""

    config_overrides = {
        "daily_minutes": 30,
        "warn_if_too_short": True,
        "warn_on_start": True,
        "warn_at_minutes": [],
        "warn_at_percent": [],
        "grace_seconds": 0,
    }

    def test_title_duration_from_ticks(self):
        session = self.emby.add_session(
            "s1", "u-kid", "Enfant1", runtime_seconds=5400, position_seconds=600
        )
        duree, reste = eq.Monitor.title_duration(session)
        self.assertAlmostEqual(duree, 5400)
        self.assertAlmostEqual(reste, 4800)

    def test_no_duration_means_no_guess(self):
        """Direct TV, flux : sans RunTimeTicks on ne previent pas."""
        session = self.emby.add_session(
            "s1", "u-kid", "Enfant1", runtime_seconds=None
        )
        self.assertIsNone(eq.Monitor.title_duration(session))
        self.tick()
        self.assertEqual(self.emby.messages[0][1]["Header"], "Bon film")

    def test_warning_when_the_film_does_not_fit(self):
        # 30 min de quota, film de 1h30
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", item="Le Grand Bleu", runtime_seconds=5400
        )
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        header, texte = (
            self.emby.messages[0][1]["Header"],
            self.emby.messages[0][1]["Text"],
        )
        self.assertEqual(header, "Attention")
        self.assertIn("30m00", texte)   # quota restant
        self.assertIn("1h30", texte)    # duree restante du film
        self.assertIn("1h00", texte)    # ce qui manque

    def test_normal_message_when_the_film_fits(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", runtime_seconds=1200)
        self.tick()
        self.assertEqual(self.emby.messages[0][1]["Header"], "Bon film")

    def test_position_is_taken_into_account(self):
        """Reprendre un film aux trois quarts peut tenir dans le quota."""
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", runtime_seconds=5400, position_seconds=4500
        )
        self.tick()
        self.assertEqual(self.emby.messages[0][1]["Header"], "Bon film")

    def test_works_without_the_start_message(self):
        """Le message 'trop court' peut etre le seul actif."""
        self.cfg.warn_on_start = False
        self.emby.add_session("s1", "u-kid", "Enfant1", runtime_seconds=1200)
        self.tick()
        self.assertEqual(self.emby.messages, [])   # ce film rentre : rien
        self.emby.sessions.clear()
        self.tick(20)
        self.emby.add_session("s2", "u-kid", "Enfant1", runtime_seconds=5400)
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)
        self.assertEqual(self.emby.messages[0][1]["Header"], "Attention")

    def test_can_be_disabled(self):
        self.cfg.warn_if_too_short = False
        self.emby.add_session("s1", "u-kid", "Enfant1", runtime_seconds=5400)
        self.tick()
        self.assertEqual(self.emby.messages[0][1]["Header"], "Bon film")

    def test_only_once_per_title(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", runtime_seconds=5400)
        self.tick()
        self.tick(20)
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)

    def test_next_title_is_evaluated_again(self):
        session = self.emby.add_session(
            "s1", "u-kid", "Enfant1", runtime_seconds=1200
        )
        self.tick()
        self.assertEqual(self.emby.messages[0][1]["Header"], "Bon film")
        session["NowPlayingItem"] = {
            "Id": "item-2",
            "Name": "Un long film",
            "RunTimeTicks": 3 * 3600 * 10_000_000,
        }
        self.tick(20)
        self.assertEqual(self.emby.messages[1][1]["Header"], "Attention")

    def test_template_variables(self):
        self.cfg.tooshort_text = (
            "%titre% dure %duree_film% (reste %restant_film%), "
            "quota %tempsrestant%, manque %manque%"
        )
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", item="Dune",
            runtime_seconds=5400, position_seconds=1800,
        )
        self.tick()
        self.assertEqual(
            self.emby.messages[0][1]["Text"],
            "Dune dure 1h30 (reste 1h00), quota 30m00, manque 30m00",
        )

    def test_event_is_journalled(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", runtime_seconds=5400)
        self.tick()
        self.assertIn("trop long", self.store.events(limit=1)[0]["detail"])

    def test_enabled_by_default(self):
        self.assertTrue(eq.Config(api_key="k").warn_if_too_short)


class TestLanguage(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(eq.i18n.normalize("EN"), "en")
        self.assertEqual(eq.i18n.normalize("fr-FR"), "fr")
        self.assertEqual(eq.i18n.normalize("de"), "fr")   # repli
        self.assertEqual(eq.i18n.normalize(""), "fr")

    def test_default_is_french(self):
        cfg = eq.Config(api_key="k")
        self.assertEqual(cfg.language, "fr")
        self.assertEqual(cfg.label("weekly"), "semaine")
        self.assertEqual(cfg.phrase("monthly"), "le mois")

    def test_switching_translates_the_shipped_templates(self):
        cfg = eq.Config(api_key="k")
        bascules = cfg.apply_language("en")
        self.assertIn("login_text", bascules)
        self.assertEqual(cfg.language, "en")
        self.assertEqual(cfg.label("weekly"), "week")
        self.assertEqual(cfg.phrase("monthly"), "this month")
        self.assertIn("you have", cfg.login_text.lower())
        self.assertIn("Enjoy", cfg.login_text)

    def test_customised_templates_are_never_overwritten(self):
        cfg = eq.Config(api_key="k")
        cfg.login_text = "Salut %pseudo% !"
        cfg.start_text = "mon texte a moi"
        bascules = cfg.apply_language("en")
        self.assertEqual(cfg.login_text, "Salut %pseudo% !")
        self.assertEqual(cfg.start_text, "mon texte a moi")
        self.assertNotIn("login_text", bascules)
        self.assertIn("stop_text", bascules)   # celui-la etait reste par defaut

    def test_round_trip_fr_en_fr(self):
        cfg = eq.Config(api_key="k")
        original = cfg.login_text
        cfg.apply_language("en")
        cfg.apply_language("fr")
        self.assertEqual(cfg.login_text, original)

    def test_invalid_language_is_rejected(self):
        cfg = eq.Config(api_key="k", language="de")
        with self.assertRaises(ValueError):
            cfg.validate()

    def test_ini_sets_the_language_and_the_defaults(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False, encoding="utf-8"
        )
        handle.write("[server]\napi_key = k\n[daemon]\nlanguage = en\n")
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        cfg = eq.load_config(handle.name)
        self.assertEqual(cfg.language, "en")
        self.assertIn("Enjoy", cfg.login_text)
        self.assertEqual(cfg.label("daily"), "day")

    def test_ini_template_overrides_the_language_default(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False, encoding="utf-8"
        )
        handle.write(
            "[server]\napi_key = k\n[daemon]\nlanguage = en\n"
            "[enforcement]\nlogin_text = Coucou %pseudo%\n"
        )
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        cfg = eq.load_config(handle.name)
        self.assertEqual(cfg.login_text, "Coucou %pseudo%")
        # les gabarits non surcharges restent dans la langue choisie
        self.assertIn("watch time", cfg.start_text)

    def test_summary_phrase_in_english(self):
        restants = {"daily": 2700.0, "weekly": 12000.0, "monthly": None}
        self.assertEqual(
            eq.Monitor.summary_phrase(restants, None, "en"),
            "3h20 this week and 45m00 today",
        )
        self.assertEqual(
            eq.Monitor.summary_phrase(restants, None, "fr"),
            "3h20 pour la semaine et 45m00 pour la journee",
        )

    def test_variable_help_is_translated(self):
        fr = dict(eq.i18n.template_help("fr"))
        en = dict(eq.i18n.template_help("en"))
        self.assertEqual(fr["pseudo"], "nom de l'utilisateur Emby")
        self.assertEqual(en["user"], "Emby user name")
        # meme nombre d'entrees, et aucune description francaise cote anglais
        self.assertEqual(len(fr), len(en))
        for nom, aide in en.items():
            self.assertNotIn("temps", aide.lower(), f"{nom} non traduit")
            self.assertNotIn("duree", aide.lower(), f"{nom} non traduit")

    def test_variable_help_uses_the_language_names(self):
        noms_en = {nom for nom, _ in eq.i18n.template_help("en")}
        self.assertIn("user", noms_en)
        self.assertIn("remaining_daily", noms_en)
        self.assertNotIn("pseudo", noms_en)
        # ces noms doivent tous etre resolus par le moteur de gabarit
        variables = {n: "x" for n in noms_en}
        for nom in noms_en:
            self.assertEqual(eq.render_template(f"%{nom}%", variables), "x")

    def test_french_variable_names_all_resolve(self):
        noms_fr = [nom for nom, _ in eq.i18n.template_help("fr")]
        cibles = {eq.TEMPLATE_ALIASES.get(n, n) for n in noms_fr}
        variables = {c: "x" for c in cibles}
        for nom in noms_fr:
            self.assertEqual(
                eq.render_template(f"%{nom}%", variables), "x", f"%{nom}% non resolu"
            )

    def test_states_and_exemptions_are_translated(self):
        self.assertEqual(eq.i18n.state_label("LECTURE", "en"), "PLAYING")
        self.assertEqual(eq.i18n.state_label("LECTURE", "fr"), "LECTURE")
        self.assertEqual(eq.i18n.state_label("inconnu", "en"), "inconnu")
        self.assertEqual(eq.i18n.exempt_reason("user", "en"), "exempt user")
        self.assertEqual(
            eq.i18n.exempt_reason("network", "en", net="10.0.0.0/8"),
            "exempt network (10.0.0.0/8)",
        )

    def test_ui_strings(self):
        self.assertEqual(eq.i18n.t("tab_config", "fr"), "Configuration")
        self.assertEqual(eq.i18n.t("tab_config", "en"), "Settings")
        self.assertEqual(eq.i18n.t("cle_inexistante", "en"), "cle_inexistante")

    def test_every_ui_key_exists_in_both_languages(self):
        fr, en = set(eq.i18n.UI["fr"]), set(eq.i18n.UI["en"])
        self.assertEqual(fr - en, set(), "cles manquantes en anglais")
        self.assertEqual(en - fr, set(), "cles manquantes en francais")

    def test_every_template_exists_in_both_languages(self):
        fr = set(eq.i18n.DEFAULT_TEMPLATES["fr"])
        en = set(eq.i18n.DEFAULT_TEMPLATES["en"])
        self.assertEqual(fr, en)


class TestEnglishMessages(BaseCase):
    config_overrides = {
        "language": "en",
        "daily_minutes": 60,
        "weekly_minutes": 300,
        "warn_on_login": True,
        "warn_at_minutes": [],
        "warn_at_percent": [],
    }

    def setUp(self) -> None:
        super().setUp()
        self.cfg.apply_language("en")
        self.monitor.reload_config(self.cfg)

    def test_login_message_is_in_english(self):
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        texte = self.emby.messages[0][1]["Text"]
        self.assertIn("you have", texte.lower())
        self.assertIn("this week", texte)
        self.assertIn("today", texte)
        self.assertNotIn("journee", texte)

    def test_greeting_is_translated(self):
        self.cfg.login_text = "%bonjour%"
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(self.emby.messages[0][1]["Text"], "Hello")

    def test_exemption_reason_is_in_english(self):
        self.cfg.exempt_users = ["Alice"]
        self.monitor.reload_config(self.cfg)
        self.emby.add_session("s1", "u-adm", "Alice")
        snap = eq.build_snapshot(self.cfg, self.monitor, self.store)
        alice = next(u for u in snap.users if u.user_name == "Alice")
        self.assertEqual(alice.exempt, "exempt user")


    def test_unlimited_word_is_translated(self):
        self.cfg.monthly_minutes = 0
        self.cfg.login_text = "%tempsrestant_mois%"
        self.tick()
        self.emby.add_session("s1", "u-kid", "Enfant1", item=None)
        self.tick(20)
        self.assertEqual(self.emby.messages[0][1]["Text"], "unlimited")


class TestPercentScope(BaseCase):
    """Par defaut, les paliers en % portent sur le quota MENSUEL."""

    config_overrides = {
        "daily_minutes": 60,
        "weekly_minutes": 300,
        "monthly_minutes": 1200,
        "warn_at_percent": [80],
        "warn_at_minutes": [],
        "warn_on_start": False,
        "grace_seconds": 0,
    }

    def seed(self, scope: str, seconds: float) -> None:
        key = eq.scope_key(datetime.fromtimestamp(self.clock()), scope, self.cfg)
        row = self.store.get_usage("u-kid", key)
        row.user_name = "Enfant1"
        row.seconds = seconds
        self.store.save_usage(row)

    def warned(self, scope: str) -> set:
        key = eq.scope_key(datetime.fromtimestamp(self.clock()), scope, self.cfg)
        return self.store.get_usage("u-kid", key).warned_tokens()

    def test_default_scope_is_monthly(self):
        self.assertEqual(self.cfg.warn_percent_scope, "monthly")
        self.assertEqual(eq.Config(api_key="k").warn_percent_scope, "monthly")

    def test_daily_at_80_percent_does_not_trigger(self):
        """80 % de la journee n'est pas un evenement : seul le mois compte."""
        self.cfg.warn_text = "%pourcentage% % de %periode_phrase%"
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed("daily", 48 * 60)     # 80 % du jour
        self.seed("weekly", 60 * 60)    # 20 % de la semaine
        self.seed("monthly", 120 * 60)  # 10 % du mois
        self.tick()
        self.assertEqual(self.emby.messages, [])
        self.assertEqual(self.warned("daily"), set())

    def test_monthly_at_80_percent_triggers(self):
        self.cfg.warn_text = "%pourcentage% % de %periode_phrase%"
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed("monthly", 960 * 60)  # 80 % du mois
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.assertIn("le mois", self.emby.messages[0][1]["Text"])
        self.assertIn("80 %", self.emby.messages[0][1]["Text"])
        # le palier est memorise sur la ligne du mois, pas sur celle du jour
        self.assertEqual(self.warned("monthly"), {"p80"})
        self.assertEqual(self.warned("daily"), set())

    def test_scope_can_be_moved_to_the_week(self):
        self.cfg.warn_percent_scope = "weekly"
        self.cfg.warn_text = "%periode_phrase%"
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed("weekly", 240 * 60)   # 80 % de la semaine
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.assertIn("la semaine", self.emby.messages[0][1]["Text"])

    def test_no_message_when_the_scope_has_no_limit(self):
        self.cfg.monthly_minutes = 0    # suivi mais sans limite
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed("monthly", 5000 * 60)
        self.tick()
        self.assertEqual(self.emby.messages, [])

    def test_no_message_when_the_scope_is_not_tracked(self):
        self.cfg.monthly_minutes = None  # periode non suivie
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed("daily", 59 * 60)
        self.tick()
        self.assertEqual(self.emby.messages, [])

    def test_minutes_still_use_the_binding_scope(self):
        """Les paliers en minutes restent sur la periode qui coupe."""
        self.cfg.warn_at_minutes = [5]
        self.cfg.warn_at_percent = []
        self.cfg.warn_text = "%periode_phrase%"
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed("daily", 56 * 60)     # reste 4 min sur la journee
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.assertIn("la journee", self.emby.messages[0][1]["Text"])

    def test_minutes_win_over_percent_in_the_same_cycle(self):
        self.cfg.warn_at_minutes = [5]
        self.cfg.warn_text = "%periode_phrase%"
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.seed("daily", 56 * 60)     # palier minutes
        self.seed("monthly", 960 * 60)  # palier pourcentage
        self.tick()
        self.assertEqual(len(self.emby.messages), 1)
        self.assertIn("la journee", self.emby.messages[0][1]["Text"])
        self.tick(20)                   # le cycle suivant traite le pourcentage
        self.assertEqual(len(self.emby.messages), 2)
        self.assertIn("le mois", self.emby.messages[1][1]["Text"])

    def test_invalid_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            make_config(warn_percent_scope="annuel").validate()


class TestClientCapabilities(BaseCase):
    """Un client qui n'affiche pas les messages doit etre identifie, pas subi."""

    config_overrides = {
        "daily_minutes": 1,
        "warn_on_login": True,
        "warn_at_minutes": [],
        "warn_at_percent": [],
        "grace_seconds": 0,
    }

    def test_capability_detection(self):
        self.assertTrue(
            eq.session_can_display_message({"SupportedCommands": ["DisplayMessage"]})
        )
        self.assertFalse(
            eq.session_can_display_message({"SupportedCommands": ["GoHome"]})
        )
        self.assertFalse(eq.session_can_display_message({"SupportedCommands": []}))
        # capacites non declarees : on ne presume rien
        self.assertIsNone(eq.session_can_display_message({}))

    def test_snapshot_reports_the_capability(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.emby.add_session(
            "s2", "u-guest", "Invite", supported_commands=["GoHome"]
        )
        self.emby.add_user("u-guest", "Invite")
        snap = eq.build_snapshot(self.cfg, self.monitor, self.store)
        par_id = {s.session_id: s for s in snap.sessions}
        self.assertTrue(par_id["s1"].can_message)
        self.assertFalse(par_id["s2"].can_message)

    def test_remote_control_refusal_is_reported(self):
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", supports_remote_control=False
        )
        snap = eq.build_snapshot(self.cfg, self.monitor, self.store)
        self.assertFalse(snap.sessions[0].can_control)

    def test_warning_logged_once_per_session(self):
        self.tick()  # amorcage, aucune session
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", item=None, supported_commands=["GoHome"]
        )
        with self.assertLogs(eq.LOG, level=logging.WARNING) as captured:
            self.tick(20)
        self.assertIn("ne declare pas DisplayMessage", "\n".join(captured.output))
        # une seule fois : on ne remplit pas le journal a chaque cycle
        self.assertIn("s1", self.monitor._muettes)

    def test_message_is_still_sent(self):
        """On previent, mais on envoie quand meme : le client peut evoluer."""
        self.tick()  # amorcage
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", item=None, supported_commands=["GoHome"]
        )
        self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)

    def test_stop_still_works_on_a_silent_client(self):
        """Ne pas afficher de message n'empeche pas de couper."""
        self.cfg.warn_on_login = False
        self.emby.add_session(
            "s1", "u-kid", "Enfant1", supported_commands=["GoHome"]
        )
        self.tick()
        for _ in range(3):
            self.tick(20)
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])



class TestStoppedMessage(BaseCase):
    """Un message dedie au moment exact de la coupure."""

    config_overrides = {
        "daily_minutes": 1,
        "warn_at_minutes": [],
        "warn_at_percent": [],
        "warn_on_start": False,
        "grace_seconds": 20,
    }

    def test_notice_then_final_message_then_stop(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        for _ in range(3):
            self.tick(20)
        # quota atteint : preavis seul, le film tourne encore
        self.assertEqual(len(self.emby.messages), 1)
        self.assertEqual(self.emby.messages[0][1]["Header"], "Quota atteint")
        self.assertIn("va s'arreter", self.emby.messages[0][1]["Text"])
        self.assertEqual(self.emby.playstate, [])

        self.tick(20)   # fin du delai de grace
        self.assertEqual(len(self.emby.messages), 2)
        self.assertEqual(self.emby.messages[1][1]["Header"], "Quota epuise")
        self.assertIn("arret du film", self.emby.messages[1][1]["Text"])
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])

    def test_final_message_precedes_the_stop_command(self):
        """L'ordre compte : le message doit partir avant la commande d'arret."""
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        for _ in range(4):
            self.tick(20)
        appels = [
            chemin
            for methode, chemin, _ in self.emby.calls
            if methode == "POST" and "/s1/" in chemin
        ]
        self.assertEqual(appels[-2:], ["/Sessions/s1/Message", "/Sessions/s1/Playing/Stop"])

    def test_no_notice_without_grace(self):
        """Sans delai de grace, le preavis ferait doublon : un seul message."""
        self.cfg.grace_seconds = 0
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        for _ in range(3):
            self.tick(20)
        self.assertEqual(len(self.emby.messages), 1)
        self.assertEqual(self.emby.messages[0][1]["Header"], "Quota epuise")
        self.assertEqual(self.emby.playstate, [("s1", "Stop")])

    def test_grace_variable(self):
        self.cfg.stop_text = "arret dans %delai%"
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        for _ in range(3):
            self.tick(20)
        self.assertEqual(self.emby.messages[0][1]["Text"], "arret dans 20s")

    def test_final_message_has_its_own_duration(self):
        self.cfg.stopped_timeout_seconds = 30
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        for _ in range(4):
            self.tick(20)
        self.assertEqual(self.emby.messages[-1][1]["TimeoutMs"], 30000)

    def test_sent_on_every_device(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", device="TV")
        self.emby.add_session("s2", "u-kid", "Enfant1", device="Tablette")
        self.tick()
        for _ in range(4):
            self.tick(20)
        finaux = [
            sid for sid, m in self.emby.messages if m["Header"] == "Quota epuise"
        ]
        self.assertEqual(set(finaux), {"s1", "s2"})


class TestSnapshot(BaseCase):
    config_overrides = {"default_minutes": 60, "warn_at_minutes": [10]}

    def test_users_sessions_and_period(self):
        self.emby.add_session("s1", "u-kid", "Enfant1", item="Le Grand Bleu")
        self.emby.add_session("s2", "u-adm", "Alice", item="Dune")
        self.tick()
        self.tick(120)
        snap = eq.build_snapshot(self.cfg, self.monitor, self.store, running=True)
        self.assertTrue(snap.ok)
        self.assertTrue(snap.running)
        self.assertEqual(snap.period, "daily")
        by_name = {u.user_name: u for u in snap.users}
        self.assertAlmostEqual(by_name["Enfant1"].used, 60.0, delta=1)
        self.assertEqual(by_name["Enfant1"].quota, 3600)
        self.assertAlmostEqual(by_name["Enfant1"].remaining, 3540, delta=1)
        self.assertEqual(by_name["Enfant1"].state, "LECTURE")
        # aucune exemption automatique : Alice est compte comme les autres
        self.assertEqual(by_name["Alice"].exempt, "")
        states = {s.user_name: s.state for s in snap.sessions}
        self.assertEqual(states, {"Enfant1": "LECTURE", "Alice": "LECTURE"})

    def test_paused_and_idle_sessions(self):
        session = self.emby.add_session("s1", "u-kid", "Enfant1")
        session["PlayState"]["IsPaused"] = True
        self.emby.add_session("s2", "u-guest", "Invite", item=None)
        self.emby.add_user("u-guest", "Invite")
        snap = eq.build_snapshot(self.cfg, self.monitor, self.store)
        states = {s.user_name: s.state for s in snap.sessions}
        self.assertEqual(states["Enfant1"], "PAUSE")
        self.assertEqual(states["Invite"], "INACTIVE")

    def test_server_error_is_reported_without_losing_counters(self):
        row = self.usage()
        row.user_name = "Enfant1"
        row.seconds = 300
        self.store.save_usage(row)
        self.emby.stop()  # serveur coupe
        snap = eq.build_snapshot(self.cfg, self.monitor, self.store)
        self.assertFalse(snap.ok)
        self.assertTrue(snap.error)
        self.assertEqual(snap.sessions, [])
        self.assertIn("Enfant1", {u.user_name for u in snap.users})

    def test_snapshot_does_not_disturb_accounting(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        avant = dict(self.monitor._last_seen)
        eq.build_snapshot(self.cfg, self.monitor, self.store)
        self.assertEqual(self.monitor._last_seen, avant)
        self.tick(20)
        self.assertAlmostEqual(self.usage().seconds, 20.0)

    def test_bonus_and_stop_count_visible(self):
        eq.grant_bonus(self.cfg, self.store, "u-kid", "Enfant1", 30, now=self.now())
        snap = eq.build_snapshot(self.cfg, self.monitor, self.store)
        user = next(u for u in snap.users if u.user_name == "Enfant1")
        self.assertEqual(user.bonus, 1800)
        self.assertEqual(user.allowed, 3600 + 1800)
        self.assertEqual(snap.events[0]["kind"], "grant")

    def test_disabled_account_flagged(self):
        self.store.set_disabled("u-kid", "Enfant1", self.clock() + 600)
        snap = eq.build_snapshot(self.cfg, self.monitor, self.store)
        user = next(u for u in snap.users if u.user_name == "Enfant1")
        self.assertIsNotNone(user.disabled_until)

    def test_ratio_is_clamped(self):
        user = make_user_view(used=7200, quota=3600)
        self.assertEqual(user.ratio, 1.0)
        self.assertEqual(user.remaining, 0.0)
        exempt = make_user_view(used=10, quota=0, exempt="administrateur")
        self.assertTrue(exempt.unlimited)
        self.assertEqual(exempt.ratio, 0.0)


class TestActions(BaseCase):
    config_overrides = {"default_minutes": 60}

    def test_grant_bonus_resets_warnings_and_stops(self):
        row = self.usage()
        row.user_name = "Enfant1"
        row.warned = "10,5"
        row.stop_count = 3
        self.store.save_usage(row)
        after = eq.grant_bonus(self.cfg, self.store, "u-kid", "Enfant1", 20, now=self.now())["daily"]
        self.assertEqual(after.bonus_secs, 1200)
        self.assertEqual(after.warned, "")
        self.assertEqual(after.stop_count, 0)

    def test_grant_bonus_never_goes_negative(self):
        eq.grant_bonus(self.cfg, self.store, "u-kid", "Enfant1", 10, now=self.now())
        after = eq.grant_bonus(self.cfg, self.store, "u-kid", "Enfant1", -60, now=self.now())["daily"]
        self.assertEqual(after.bonus_secs, 0.0)

    def test_reset_user_clears_counter(self):
        row = self.usage()
        row.user_name = "Enfant1"
        row.seconds = 999
        self.store.save_usage(row)
        eq.reset_user(self.cfg, self.store, "u-kid", "Enfant1", now=self.now())
        self.assertEqual(self.usage().seconds, 0.0)

    def test_reload_config_updates_exemptions(self):
        self.assertNotIn("enfant1", self.monitor._exempt_names)
        nouvelle = make_config(url=self.emby.url, exempt_users=["Enfant1"],
                               exempt_networks=["10.0.0.0/8"])
        self.monitor.reload_config(nouvelle)
        self.assertIn("enfant1", self.monitor._exempt_names)
        self.assertEqual(len(self.monitor._exempt_nets), 1)
        self.emby.add_session("s1", "u-kid", "Enfant1")
        self.tick()
        self.tick(20)
        self.assertEqual(self.usage().seconds, 0.0)


class TestMonitorThread(BaseCase):
    config_overrides = {"poll_interval": 5}

    def test_start_and_stop(self):
        self.emby.add_session("s1", "u-kid", "Enfant1")
        worker = eq.MonitorThread(self.monitor)
        self.assertFalse(worker.running)
        worker.start()
        self.addCleanup(worker.stop)
        deadline = time.time() + 3
        while not self.emby.calls and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(worker.running)
        self.assertTrue(any(c[1] == "/Sessions" for c in self.emby.calls))
        worker.stop()
        self.assertFalse(worker.running)

    def test_start_is_idempotent(self):
        worker = eq.MonitorThread(self.monitor)
        worker.start()
        thread = worker._thread
        worker.start()
        self.assertIs(worker._thread, thread)
        worker.stop()


class TestRingLogHandler(unittest.TestCase):
    def test_keeps_last_lines(self):
        handler = eq.RingLogHandler(capacity=3)
        logger = logging.getLogger("test-ring")
        logger.handlers = [handler]
        logger.setLevel(logging.DEBUG)
        for i in range(5):
            logger.info("ligne %d", i)
        lignes = handler.lines()
        self.assertEqual(len(lignes), 3)
        self.assertEqual([l[2] for l in lignes], ["ligne 2", "ligne 3", "ligne 4"])
        self.assertEqual(handler.lines(1)[0][2], "ligne 4")
        self.assertEqual(lignes[0][1], "INFO")


class TestUpdateIni(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "conf.ini")

    def write(self, body: str) -> None:
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(body)

    def read(self) -> str:
        with open(self.path, encoding="utf-8") as handle:
            return handle.read()

    def test_updates_value_and_keeps_comments(self):
        self.write(
            "; en-tete\n[server]\nurl = http://nas:8096\napi_key = k\n\n"
            "[quota]\n; combien de minutes\ndefault_minutes = 120\n"
        )
        eq.update_ini(self.path, {"quota": {"default_minutes": "60"}})
        content = self.read()
        self.assertIn("; en-tete", content)
        self.assertIn("; combien de minutes", content)
        self.assertIn("default_minutes = 60", content)
        self.assertNotIn("= 120", content)
        self.assertIn("api_key = k", content)

    def test_adds_key_to_existing_section(self):
        self.write("[server]\napi_key = k\n\n[quota]\ndefault_minutes = 120\n")
        eq.update_ini(self.path, {"quota": {"period": "weekly"}})
        cfg = eq.load_config(self.path)
        self.assertEqual(cfg.period, "weekly")
        self.assertEqual(cfg.default_minutes, 120)

    def test_creates_missing_section(self):
        self.write("[server]\napi_key = k\n")
        eq.update_ini(self.path, {"users": {"enfant1": "45"}})
        cfg = eq.load_config(self.path)
        self.assertEqual(cfg.user_quotas, {"enfant1": {"daily": 45}})

    def test_deletes_key_when_value_is_none(self):
        self.write("[server]\napi_key = k\n[users]\nenfant1 = 45\nenfant2 = 60\n")
        eq.update_ini(self.path, {"users": {"enfant1": None}})
        cfg = eq.load_config(self.path)
        self.assertEqual(cfg.user_quotas, {"enfant2": {"daily": 60}})

    def test_insert_does_not_leak_into_next_section(self):
        self.write(
            "[server]\napi_key = k\n\n[quota]\ndefault_minutes = 120\n\n"
            "[enforcement]\ngrace_seconds = 20\n"
        )
        eq.update_ini(
            self.path,
            {"quota": {"period": "weekly"}, "enforcement": {"escalation": "disable_user"}},
        )
        cfg = eq.load_config(self.path)
        self.assertEqual(cfg.period, "weekly")
        self.assertEqual(cfg.escalation, "disable_user")
        self.assertEqual(cfg.grace_seconds, 20)

    def test_shipped_example_keeps_the_cooldown_off(self):
        """Le fichier livre ne doit pas reactiver un mecanisme non demande."""
        example = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "emby_quota.ini.example")
        with open(example, encoding="utf-8") as handle:
            self.write(handle.read())
        self.assertFalse(eq.load_config(self.path).login_cooldown_enabled)

    def test_round_trip_on_the_shipped_example(self):
        example = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "emby_quota.ini.example")
        with open(example, encoding="utf-8") as handle:
            self.write(handle.read())
        eq.update_ini(
            self.path,
            {
                "quota": {"default_minutes": "90", "period": "weekly"},
                "users": {"enfant1": "45"},
                "daemon": {"verbose": "1"},
            },
        )
        cfg = eq.load_config(self.path)
        self.assertEqual(cfg.default_minutes, 90)
        self.assertEqual(cfg.period, "weekly")
        self.assertEqual(cfg.user_quotas["enfant1"], {"daily": 45})
        self.assertEqual(cfg.verbose, 1)
        # les commentaires du fichier livre sont intacts
        self.assertIn("; Cle API : Tableau de bord Emby", self.read())






class TestMultilineMessages(unittest.TestCase):
    """Un message mis en page sur plusieurs lignes doit survivre a l'INI.

    Regression : le GUI ecrivait le texte brut, ce qui produisait un fichier
    invalide ("Source contains parsing errors") des la relecture.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "emby_quota.ini")
        self.base = (
            "[server]\nurl = http://x\napi_key = k\n\n"
            "[daemon]\ndb_path = :memory:\nlog_path =\n\n"
            "[quota]\ndaily_minutes = 120\n\n"
            "[enforcement]\nwarn_on_login = true\n"
        )
        self.mise_en_page = (
            "Bonjour %pseudo%,\n"
            "\n"
            "   Jour    : %tempsrestant_jour%\n"
            "   Semaine : %tempsrestant_semaine%\n"
            "\n"
            "Bon visionnage."
        )

    def write(self, contenu: str) -> None:
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(contenu)

    def read(self) -> str:
        with open(self.path, encoding="utf-8") as handle:
            return handle.read()

    # -- echappement --------------------------------------------------------

    def test_escape_round_trip(self):
        for texte in (
            "une ligne",
            "deux\nlignes",
            "   indente",
            "tabule\tici",
            "point-virgule ; garde",
            "diese # garde",
            "antislash \\ garde",
            self.mise_en_page,
        ):
            self.assertEqual(eq.unescape_ini_text(eq.escape_ini_text(texte)), texte)

    def test_escaped_value_stays_on_one_line(self):
        self.assertNotIn("\n", eq.escape_ini_text(self.mise_en_page))

    def test_unknown_escape_is_left_alone(self):
        """%tempsrestant% et consorts ne doivent pas etre abimes."""
        self.assertEqual(eq.unescape_ini_text("C:\\quotaemby"), "C:\\quotaemby")

    # -- ecriture -----------------------------------------------------------

    def test_saved_multiline_file_is_valid_ini(self):
        """Le garde-fou : le fichier ecrit doit se relire sans reparation."""
        self.write(self.base)
        eq.update_ini(self.path, {"enforcement": {"login_text": self.mise_en_page}})
        brut = configparser.ConfigParser(
            inline_comment_prefixes=(";", "#"), interpolation=None
        )
        brut.read_string(self.read())          # leve si le fichier est casse
        _texte, reparees = eq.repair_ini_text(self.read())
        self.assertEqual(reparees, [], "le fichier ecrit ne doit rien avoir a reparer")

    def test_round_trip_preserves_layout(self):
        self.write(self.base)
        eq.update_ini(self.path, {"enforcement": {"login_text": self.mise_en_page}})
        self.assertEqual(eq.load_config(self.path).login_text, self.mise_en_page)

    def test_semicolon_is_not_taken_for_a_comment(self):
        texte = "Bonjour ; bon visionnage # vraiment"
        self.write(self.base)
        eq.update_ini(self.path, {"enforcement": {"login_text": texte}})
        self.assertEqual(eq.load_config(self.path).login_text, texte)

    def test_rewrite_does_not_keep_the_old_multiline_value(self):
        """Sans cela, l'ancien texte reste colle sous le nouveau."""
        self.write(
            self.base
            + "login_text = Ancien debut,\nAncienne suite.\nAncienne fin.\n\n"
            + "[users]\nenfant1 = 45\n"
        )
        eq.update_ini(self.path, {"enforcement": {"login_text": "Nouveau texte."}})
        cfg = eq.load_config(self.path)
        self.assertEqual(cfg.login_text, "Nouveau texte.")
        self.assertNotIn("Ancienne", self.read())
        # la section suivante ne doit pas avoir ete avalee
        self.assertEqual(cfg.user_quotas["enfant1"], {"daily": 45})

    # -- lecture tolerante --------------------------------------------------

    def test_a_file_broken_by_an_old_version_still_loads(self):
        self.write(
            self.base
            + "login_text = Bonjour %pseudo%,\n\nIl vous reste du temps.\nBon visionnage.\n"
        )
        with self.assertLogs(eq.LOG, level=logging.WARNING) as captured:
            cfg = eq.load_config(self.path)
        self.assertIn("multi-ligne", "\n".join(captured.output))
        self.assertEqual(
            cfg.login_text,
            "Bonjour %pseudo%,\n\nIl vous reste du temps.\nBon visionnage.",
        )

    def test_repair_leaves_a_correct_file_untouched(self):
        exemple = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "emby_quota.ini.example")
        with open(exemple, encoding="utf-8") as handle:
            brut = handle.read()
        texte, reparees = eq.repair_ini_text(brut)
        self.assertEqual(reparees, [])
        self.assertEqual(texte, brut)

    def test_repair_ignores_comments_and_sections(self):
        texte, reparees = eq.repair_ini_text(
            "[a]\ncle = valeur\n; commentaire\n\n[b]\nautre = 1\n"
        )
        self.assertEqual(reparees, [])

    def test_settings_output_stays_on_one_line(self):
        import contextlib
        import io

        self.write(self.base)
        eq.update_ini(self.path, {"enforcement": {"login_text": self.mise_en_page}})
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            eq.main(["--config", self.path, "--settings"])
        ligne = [l for l in buffer.getvalue().splitlines() if "login_text" in l]
        self.assertEqual(len(ligne), 1)
        self.assertIn("\\n", ligne[0])






class TestFormatting(unittest.TestCase):
    def test_fmt_delta(self):
        self.assertEqual(eq.fmt_delta(0), "0s")
        self.assertEqual(eq.fmt_delta(-10), "0s")
        self.assertEqual(eq.fmt_delta(45), "45s")
        self.assertEqual(eq.fmt_delta(750), "12m30")
        self.assertEqual(eq.fmt_delta(11100), "3h05")

    def test_fmt_minutes(self):
        self.assertEqual(eq.fmt_minutes(0), "0 min")
        self.assertEqual(eq.fmt_minutes(59), "1 min")
        self.assertEqual(eq.fmt_minutes(600), "10 min")
        self.assertEqual(eq.fmt_minutes(3600), "1 h 00")
        self.assertEqual(eq.fmt_minutes(5400), "1 h 30")

    def test_warned_tokens_parsing(self):
        row = eq.UsageRow(user_id="u", period_key="p", warned="m10,m5,p80")
        self.assertEqual(row.warned_tokens(), {"m10", "m5", "p80"})
        self.assertEqual(eq.UsageRow(user_id="u", period_key="p").warned_tokens(), set())
        row.mark_warned({"m1", "m5"})
        self.assertEqual(row.warned_tokens(), {"m10", "m5", "m1", "p80"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
