#!/usr/bin/env python3
"""Run an isolated OpenSSH fixture. Requires passwordless sudo, never changes system sshd."""
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    project = Path(__file__).resolve().parents[1]
    root = Path(tempfile.mkdtemp(prefix="ssh-key-setup-test-"))
    root.chmod(0o755)
    username = "sshks_" + secrets.token_hex(4)
    password = " " + secrets.token_hex(24) + " "
    created = False
    server = None
    log = None
    try:
        cli = root / "ssh-key-setup"
        run("go", "build", "-o", str(cli), "./cmd/ssh-key-setup", cwd=project,
            env=dict(os.environ, CGO_ENABLED="0"))
        run("sudo", "-n", "useradd", "--no-log-init", "--no-user-group", "--gid", "nogroup",
            "--create-home", "--home-dir", str(root / "server"), "--shell", "/bin/sh", username)
        created = True
        run("sudo", "-n", "chpasswd", input=f"{username}:{password}\n", text=True)
        secret_file = root / "password"
        fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(password)
        for name in ("host_key", "existing_key"):
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name))
        remote_ssh = root / "server" / ".ssh"
        run("sudo", "-n", "install", "-d", "-m", "700", "-o", username, "-g", "nogroup", str(remote_ssh))
        run("sudo", "-n", "install", "-m", "600", "-o", username, "-g", "nogroup",
            str(root / "existing_key.pub"), str(remote_ssh / "authorized_keys"))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        config = root / "sshd_config"
        config.write_text(f"""ListenAddress 127.0.0.1
Port {port}
HostKey {root / 'host_key'}
PidFile {root / 'sshd.pid'}
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
UsePAM no
StrictModes yes
PermitRootLogin no
AllowUsers {username}
Subsystem sftp internal-sftp
LogLevel VERBOSE
""")
        run("sudo", "-n", "mkdir", "-p", "/run/sshd")
        run("sudo", "-n", "/usr/sbin/sshd", "-t", "-f", str(config))
        log = (root / "server.log").open("w")
        # Hosts with restrictive TCP-wrapper policies may reject localhost.
        # Override hosts.allow only inside the fixture's private mount namespace.
        (root / "hosts.allow").write_text("sshd: 127.0.0.1: ALLOW\n")
        server = subprocess.Popen(["sudo", "-n", "unshare", "--mount", "--propagation", "private",
                                   sys.executable, str(Path(__file__).resolve()), "--serve-fixture", str(root)],
                                  stdout=log, stderr=log)
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() >= deadline or server.poll() is not None:
                    raise RuntimeError("Isolated sshd failed to start: " + (root / "server.log").read_text())
                time.sleep(0.05)
        env = dict(os.environ, SSH_SETUP_TEST_PORT=str(port), SSH_SETUP_TEST_USER=username,
                   SSH_SETUP_TEST_PASSWORD_FILE=str(secret_file), SSH_SETUP_TEST_CLI=str(cli))
        run("go", "test", "-count=1", "-v", "-run", "^TestOpenSSH$", "./internal/setup", cwd=project, env=env)
        content = subprocess.check_output(["sudo", "-n", "cat", str(remote_ssh / "authorized_keys")])
        if len(content.splitlines()) != 2:
            raise RuntimeError("Existing key was lost or a duplicate was appended")
        print("OpenSSH: installation, backup, repeat, plain ssh command, CLI password modes and wrong password: PASS")
    except Exception:
        if (root / "server.log").exists():
            print((root / "server.log").read_text(), flush=True)
        raise
    finally:
        if server is not None:
            pidfile = root / "sshd.pid"
            if pidfile.exists():
                subprocess.run(["sudo", "-n", "kill", "-TERM", pidfile.read_text().strip()], check=False)
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                subprocess.run(["sudo", "-n", "kill", "-TERM", str(server.pid)], check=False)
                server.wait(timeout=5)
        if log:
            log.close()
        if created:
            subprocess.run(["sudo", "-n", "userdel", username], check=False)
        # Only remove the unique fixture directory created above.
        subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(root)], check=False)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--serve-fixture":
        fixture = Path(sys.argv[2])
        if Path("/etc/hosts.allow").exists():
            run("mount", "--bind", str(fixture / "hosts.allow"), "/etc/hosts.allow")
        os.execv("/usr/sbin/sshd", ["/usr/sbin/sshd", "-D", "-e", "-f", str(fixture / "sshd_config")])
    else:
        main()
