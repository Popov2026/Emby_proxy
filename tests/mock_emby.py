#!/usr/bin/env python3
"""mock_emby.py - Faux serveur Emby pour tester emby_quota.py sans toucher au vrai.

Implemente le sous-ensemble d'API utilise par emby_quota :
    GET  /Sessions
    POST /Sessions/{Id}/Message
    POST /Sessions/{Id}/Playing/{Command}
    GET  /Users
    GET  /Users/{Id}
    POST /Users/{Id}/Policy

Toutes les requetes recues sont enregistrees dans `server.calls` pour les
assertions de test. Utilisable en bibliotheque (MockEmby) ou en standalone :

    python3 mock_emby.py --port 8096 --api-key test
"""

from __future__ import annotations

import argparse
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional


def make_user(user_id: str, name: str, admin: bool = False) -> dict:
    return {
        "Id": user_id,
        "Name": name,
        "Policy": {
            "IsAdministrator": admin,
            "IsDisabled": False,
            "EnableAllFolders": True,
            "MaxParentalRating": None,
            "BlockedTags": [],
        },
    }


def make_session(
    session_id: str,
    user_id: str,
    user_name: str,
    item: Optional[str] = "Un film",
    paused: bool = False,
    runtime_seconds: Optional[float] = 5400,
    position_seconds: float = 0.0,
    endpoint: str = "10.8.0.5:51234",
    client: str = "Emby Android",
    device: str = "Pixel",
    supports_remote_control: bool = True,
    supported_commands: Optional[List[str]] = None,
    last_activity: Optional[str] = None,
) -> dict:
    session: Dict[str, Any] = {
        "Id": session_id,
        "UserId": user_id,
        "UserName": user_name,
        "Client": client,
        "DeviceName": device,
        "RemoteEndPoint": endpoint,
        "PlayState": {
            "IsPaused": paused,
            "PositionTicks": int(position_seconds * 10_000_000),
        },
        "LastActivityDate": last_activity,
        "SupportsRemoteControl": supports_remote_control,
        "SupportedCommands": (
            ["DisplayMessage", "GoHome", "SetVolume"]
            if supported_commands is None
            else list(supported_commands)
        ),
    }
    if item is not None:
        now_playing = {"Name": item, "Id": "item-1", "Type": "Movie"}
        if runtime_seconds is not None:
            # Emby exprime les durees en ticks de 100 ns
            now_playing["RunTimeTicks"] = int(runtime_seconds * 10_000_000)
        session["NowPlayingItem"] = now_playing
    return session


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- helpers -----------------------------------------------------------

    @property
    def state(self) -> "MockEmby":
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *args) -> None:  # silence
        pass

    def _auth_ok(self) -> bool:
        if not self.state.api_key:
            return True
        token = self.headers.get("X-Emby-Token")
        if token == self.state.api_key:
            return True
        query = urllib.parse.urlparse(self.path).query
        return urllib.parse.parse_qs(query).get("api_key", [None])[0] == self.state.api_key

    def _send(self, code: int, payload: Optional[Any] = None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _body(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return None

    # -- routage -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        self.state.calls.append(("GET", path, None))
        if path != "/__debug/recordings" and not self._auth_ok():
            return self._send(401, {"Error": "Unauthorized"})
        if path == "/__debug/recordings":
            # non standard : sert aux tests de bout en bout inter-processus
            return self._send(
                200,
                {
                    "messages": self.state.messages,
                    "playstate": self.state.playstate,
                    "policy_updates": self.state.policy_updates,
                    "commands": self.state.commands,
                },
            )
        if path == "/Sessions":
            return self._send(200, self.state.sessions)
        if path == "/Users":
            return self._send(200, list(self.state.users.values()))
        if path.startswith("/Users/"):
            user_id = path.split("/")[2]
            user = self.state.users.get(user_id)
            return self._send(200, user) if user else self._send(404, {"Error": "NotFound"})
        self._send(404, {"Error": "NotFound"})

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        body = self._body()
        self.state.calls.append(("POST", path, body))
        if not self._auth_ok():
            return self._send(401, {"Error": "Unauthorized"})

        parts = [p for p in path.split("/") if p]
        # /Sessions/{id}/Message
        if len(parts) == 3 and parts[0] == "Sessions" and parts[2] == "Message":
            self.state.messages.append((parts[1], body or {}))
            return self._send(204)
        # /Sessions/{id}/Command/{name} (autre route pour DisplayMessage)
        if len(parts) == 4 and parts[0] == "Sessions" and parts[2] == "Command":
            arguments = (body or {}).get("Arguments", {})
            self.state.commands.append((parts[1], parts[3], arguments))
            if parts[3] == "DisplayMessage":
                self.state.messages.append((parts[1], arguments))
            return self._send(204)
        # /Sessions/{id}/Playing/{cmd}
        if len(parts) == 4 and parts[0] == "Sessions" and parts[2] == "Playing":
            session_id, command = parts[1], parts[3]
            self.state.playstate.append((session_id, command))
            if command.lower() == "stop":
                self.state.sessions = [
                    s for s in self.state.sessions if s.get("Id") != session_id
                ]
            return self._send(204)
        # /Users/{id}/Policy
        if len(parts) == 3 and parts[0] == "Users" and parts[2] == "Policy":
            user_id = parts[1]
            user = self.state.users.get(user_id)
            if not user:
                return self._send(404, {"Error": "NotFound"})
            user["Policy"] = body or {}
            self.state.policy_updates.append((user_id, dict(user["Policy"])))
            return self._send(204)
        self._send(404, {"Error": "NotFound"})


class MockEmby:
    """Serveur Emby factice, demarre sur un port libre."""

    def __init__(self, api_key: str = "test-key", port: int = 0) -> None:
        self.api_key = api_key
        self.users: Dict[str, dict] = {}
        self.sessions: List[dict] = []
        self.messages: List[tuple] = []
        self.playstate: List[tuple] = []
        self.policy_updates: List[tuple] = []
        self.commands: List[tuple] = []
        self.calls: List[tuple] = []
        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        self._httpd.state = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "MockEmby":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "MockEmby":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- helpers de scenario ------------------------------------------------

    def add_user(self, user_id: str, name: str, admin: bool = False) -> dict:
        user = make_user(user_id, name, admin)
        self.users[user_id] = user
        return user

    def add_session(self, *args, **kwargs) -> dict:
        session = make_session(*args, **kwargs)
        self.sessions.append(session)
        return session

    def clear_recordings(self) -> None:
        self.messages.clear()
        self.playstate.clear()
        self.policy_updates.clear()
        self.commands.clear()
        self.calls.clear()


def main() -> int:  # pragma: no cover - usage manuel
    parser = argparse.ArgumentParser(description="Faux serveur Emby")
    parser.add_argument("--port", type=int, default=8096)
    parser.add_argument("--api-key", default="test-key")
    args = parser.parse_args()
    server = MockEmby(api_key=args.api_key, port=args.port)
    server.add_user("u-admin", "Alice", admin=True)
    server.add_user("u-kid", "Enfant1")
    server.add_user("u-guest", "Invite")
    # scenario par defaut : deux comptes en lecture (aucun n'est exempte :
    # le statut administrateur ne dispense de rien) et une session inactive
    server.add_session(
        "s1", "u-kid", "Enfant1", item="Le Grand Bleu",
        endpoint="10.8.0.5:51234", client="Emby Android", device="Pixel",
    )
    server.add_session(
        "s2", "u-admin", "Alice", item="Dune",
        endpoint="192.168.1.20:44100", client="Emby Web", device="Firefox",
    )
    server.add_session(
        "s3", "u-guest", "Invite", item=None,
        endpoint="192.168.1.31:5001", client="Emby Theater", device="Salon",
    )
    server.start()
    print(f"Mock Emby sur {server.url} (cle : {args.api_key}) - Ctrl+C pour arreter")
    try:
        while True:
            import time

            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
