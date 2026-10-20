#!/usr/bin/env python3
"""Install the manager locally without applying firewall or systemd changes."""
import argparse
import importlib.util
import os
from pathlib import Path
import sys

RELEASES = Path("/opt/nft-forward-manager/releases")
LAUNCHER = Path("/usr/local/bin/nft-forward")


def install(root, config=None, manager=None):
    root = Path(root).resolve()
    version = (root / "VERSION").read_text().strip()
    import re
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid package version")
    if manager is None:
        spec = importlib.util.spec_from_file_location("manager", root / "po0-nft-forward.py")
        manager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manager)
    candidate = manager.load(Path(config)) if config else None
    desired = manager.DESIRED
    if candidate and desired.exists():
        raise ValueError("Existing desired.json preserved. Use the existing config or replace it explicitly.")
    # Keep the existing program used by the active service until an explicit apply.
    release = RELEASES / version
    for name in ("po0-nft-forward.py", "po0-forwarding.example.json", "VERSION", "README.md"):
        manager.atomic_write(release / name, (root / name).read_bytes(), 0o644)
    if candidate:
        with manager.locked():
            if desired.exists():
                raise ValueError("desired.json appeared during install; preserving it.")
            manager.atomic_write(desired, manager.json_text(candidate))
    elif not desired.exists() and manager.ACTIVE.exists():
        with manager.locked():
            if not desired.exists():
                manager.atomic_write(desired, manager.json_text(manager.load(manager.ACTIVE)))
    launcher = ('#!/bin/sh\nexec /usr/bin/python3 ' + str(release / "po0-nft-forward.py") +
                ' --config /etc/po0-forwarding/desired.json "$@"\n')
    manager.atomic_write(LAUNCHER, launcher, 0o755)
    print("已安装 nft-forward-manager v" + version + "；运行 nft-forward 打开菜单。")
    print("安装只更新管理工具，未加载规则、重启服务或修改现有转发。")
    if not desired.exists():
        print("尚无本地 JSON 配置。先放置实际配置到 " + str(desired))
        print("现有 nftables 规则保持运行；不要用空示例替换现有规则。")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, help="first install only: private local JSON config")
    args = p.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        p.exit(1, "请在 Linux 上以 root 运行安装程序。\n")
    try:
        install(Path(__file__).resolve().parent, args.config)
    except (OSError, ValueError) as e:
        p.exit(1, "安装失败：{}\n".format(e))
