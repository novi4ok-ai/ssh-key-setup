#!/usr/bin/env python3
"""Smoke-test the static binary in target Linux userspaces. Requires Docker access."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess

IMAGES = ["debian:12", "debian:13", "ubuntu:22.04", "ubuntu:24.04", "ubuntu:26.04",
          "almalinux:8", "almalinux:9", "almalinux:10"]


def check(image):
    dist = Path(__file__).resolve().parents[1] / "dist"
    for args, code, expected in [
        (["-version"], 0, "SSH Key Setup"),
        (["-help"], 0, "-ip"),
        (["-ip", "127.0.0.1", "-u", "root", "-p", "fixture", "-port", "0"], 2, "65535"),
    ]:
        # Execute directly: the console binary does not require even the
        # container's shell or dynamic loader to run.
        result = subprocess.run(["docker", "run", "--rm", "--network", "none",
                                 "-v", f"{dist}:/app:ro", image, "/app/ssh-key-setup", *args],
                                text=True, capture_output=True, timeout=300)
        if result.returncode != code or expected not in result.stdout + result.stderr:
            print(f"{image}: FAIL\n{result.stderr}", flush=True)
            return False
    print(f"{image}: PASS", flush=True)
    return True


if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(check, IMAGES))
    raise SystemExit(0 if all(results) else 1)
