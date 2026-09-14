#!/usr/bin/env python3
"""Exercise real terminal prompts, hidden passwords and Ctrl+C using a PTY."""
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import socket
import subprocess
import tempfile
import termios
import time


class Session:
    def __init__(self, binary, home, args, graphical=False):
        self.master, self.slave = pty.openpty()
        self.output = b""
        env = dict(os.environ, HOME=str(home))
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
        env.pop("NO_COLOR", None)
        if graphical:
            env["DISPLAY"] = ":invalid"

        def terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.process = subprocess.Popen([str(binary), *args], stdin=self.slave,
                                        stdout=self.slave, stderr=self.slave,
                                        env=env, preexec_fn=terminal)

    def send(self, value):
        os.write(self.master, value.encode())

    def wait_for(self, value):
        deadline = time.monotonic() + 5
        while value.encode() not in self.output:
            if time.monotonic() >= deadline:
                raise AssertionError(f"Missing {value!r}: {self.output.decode(errors='replace')}")
            if select.select([self.master], [], [], 0.1)[0]:
                self.output += os.read(self.master, 65536)

    def cancel(self):
        self.send("\x03")
        assert self.process.wait(timeout=3) == 130
        assert termios.tcgetattr(self.slave)[3] & termios.ECHO, "Echo was not restored"
        while select.select([self.master], [], [], 0)[0]:
            self.output += os.read(self.master, 65536)

    def close(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=3)
        os.close(self.master)
        os.close(self.slave)


def main():
    binary = Path(__file__).resolve().parents[1] / "dist" / "ssh-key-setup"
    with tempfile.TemporaryDirectory(prefix="ssh-key-setup-terminal-") as directory, socket.socket() as server:
        root = Path(directory)
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = str(server.getsockname()[1])

        for name in ("help", "wizard", "flags", "cancel-password"):
            home = root / name
            home.mkdir()
            executable = binary
            args = ["-cli"] if name == "wizard" else []
            if name in ("flags", "cancel-password"):
                args = ["-ip", "127.0.0.1", "-u", "root", "-port", port]
            if name == "flags":
                args += ["-p", " fixture password "]
            session = Session(executable, home, args, graphical=name == "help")
            try:
                if name == "wizard":
                    session.wait_for("IP-адрес сервера:")
                    session.send("invalid\n")
                    session.wait_for("Введите IPv4")
                    session.send("127.0.0.1\n")
                    session.wait_for("Порт SSH [22]:")
                    session.send(port + "\n")
                    session.wait_for("Пользователь:")
                    session.send("root\n")
                if name in ("wizard", "cancel-password"):
                    session.wait_for("Пароль сервера:")
                    assert not termios.tcgetattr(session.slave)[3] & termios.ECHO
                    if name == "wizard":
                        session.send(" fixture password \n")
                if name in ("wizard", "flags"):
                    session.wait_for("Подключаемся к серверу")
                if name == "help":
                    session.wait_for("КОДЫ ЗАВЕРШЕНИЯ")
                    assert session.process.wait(timeout=3) == 0
                    assert b"\x1b[" in session.output, "Terminal help is not styled"
                    print("Terminal help: PASS", flush=True)
                    continue
                session.cancel()
                assert b"fixture password" not in session.output, "Password leaked to terminal"
                if name == "flags":
                    assert "Пароль сервера:".encode() not in session.output, "Flags prompted for input"
                print(f"Terminal {name}: PASS", flush=True)
            finally:
                session.close()


if __name__ == "__main__":
    main()
