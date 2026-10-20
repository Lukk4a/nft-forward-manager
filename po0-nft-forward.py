#!/usr/bin/env python3
"""Po0 IPv4 DNAT/SNAT manager. Python 3.9+, standard library only."""
import argparse
import base64
import contextlib
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

TABLE = "po0_forwarding"
UNIT = "po0-forwarding.service"
RULES = Path("/etc/nftables.d/po0-forwarding.nft")
SYSCTL = Path("/etc/sysctl.d/90-po0-forwarding.conf")
MANAGER = Path("/usr/local/sbin/po0-nft-manager.py")
SERVICE = Path("/etc/systemd/system") / UNIT
DESIRED = Path("/etc/po0-forwarding/desired.json")
ACTIVE = Path("/etc/po0-forwarding/active.json")
BACKUPS = Path("/var/backups/po0-forwarding")
OWNED = (RULES, SYSCTL, MANAGER, SERVICE, DESIRED, ACTIVE)
IP_FORWARD = Path("/proc/sys/net/ipv4/ip_forward")
LOCK = Path("/run/lock/po0-forwarding.lock")


class Error(Exception):
    pass


def run(*args, data=None, ok=(0,)):
    p = subprocess.run(args, input=data, text=True, encoding="utf-8",
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if p.returncode not in ok:
        raise Error("{}: {}".format(" ".join(args), p.stderr.strip() or p.stdout.strip()))
    return p


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise Error("端口必须是 1–65535 的整数。")
    return value


def ipv4(value):
    if not isinstance(value, str):
        raise Error("IPv4 地址必须使用字符串。")
    try:
        ip = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError, TypeError):
        raise Error("无效的 IPv4 地址：{}".format(value))
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or int(ip) == 0xffffffff:
        raise Error("地址不能为未指定、组播、回环或全局广播地址。")
    return str(ip)


def validate(c):
    if not isinstance(c, dict) or set(c) != {"interface", "snat_ip", "protected_tcp_ports", "rules"}:
        raise Error("配置字段应为 interface、snat_ip、protected_tcp_ports、rules。")
    if not isinstance(c["interface"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", c["interface"]):
        raise Error("无效的网卡名称。")
    ipv4(c["snat_ip"])
    if not isinstance(c["protected_tcp_ports"], list) or not isinstance(c["rules"], list):
        raise Error("protected_tcp_ports 和 rules 必须是数组。")
    protected = {22} | {port(p) for p in c["protected_tcp_ports"]}
    names, occupied = set(), set()
    for r in c["rules"]:
        if not isinstance(r, dict) or set(r) != {"name", "listen_port", "protocol", "target_ip", "target_port"}:
            raise Error("每条规则必须包含 name、listen_port、protocol、target_ip、target_port。")
        name = r["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", name) or name in names:
            raise Error("规则名称需唯一，且只含英文字母、数字、下划线或短横线，最长 48 字符。")
        names.add(name)
        p = port(r["listen_port"])
        port(r["target_port"])
        ipv4(r["target_ip"])
        if r["protocol"] not in ("tcp", "udp", "both"):
            raise Error("protocol 只支持 tcp、udp、both。")
        for proto in protocols(r):
            key = (proto, p)
            if key in occupied:
                raise Error("重复的入口：{}/{}".format(p, proto))
            if proto == "tcp" and p in protected:
                raise Error("入口 {} 属于受保护的 SSH/管理端口。".format(p))
            occupied.add(key)
    return c


def protocols(rule):
    return ("tcp", "udp") if rule["protocol"] == "both" else (rule["protocol"],)


def load(path):
    if not path.exists():
        raise Error("找不到本地配置：{}。请先放置实际 JSON 配置；安装不会自动替换现有 nftables 规则。".format(path))
    return validate(json.loads(path.read_text(encoding="utf-8-sig")))


def json_text(value):
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def render(c):
    validate(c)
    pre, post = [], []
    iface, source = c["interface"], c["snat_ip"]
    for r in c["rules"]:
        for proto in protocols(r):
            name, p, target, dest = r["name"], r["listen_port"], r["target_ip"], r["target_port"]
            pre.append('    iifname "{}" fib daddr type local {} dport {} counter dnat to {}:{} comment "{}-{}"'.format(
                iface, proto, p, target, dest, name, proto))
            # Limit SNAT to this DNAT's original port, current target and ingress.
            post.append('    iifname "{}" ct status dnat ct original proto-dst {} ip daddr {} {} dport {} counter snat to {} comment "{}-{}"'.format(
                iface, p, target, proto, dest, source, name, proto))
    return ('# Managed by po0-nft-forward.py; IPv4 only. No global flush.\n'
            'table ip ' + TABLE + ' {\n'
            '  chain prerouting {\n'
            '    type nat hook prerouting priority dstnat; policy accept;\n' + '\n'.join(pre) + '\n  }\n'
            '  chain postrouting {\n'
            '    type nat hook postrouting priority srcnat; policy accept;\n' + '\n'.join(post) + '\n  }\n}\n')


def transaction(body):
    # "add" tolerates an existing table; delete+recreate share one nft transaction.
    return "add table ip {}\ndelete table ip {}\n{}".format(TABLE, TABLE, body or "")


def require_host():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise Error("此操作需在 Po0 的 Linux 系统中以 root 运行。list/render 可在本机使用。")
    for cmd in ("nft", "ip", "ss", "sysctl", "systemctl"):
        if not shutil.which(cmd):
            raise Error("缺少依赖：{}；请先安装对应的系统软件包。".format(cmd))
    if not Path("/usr/bin/python3").is_file() or not Path("/run/systemd/system").is_dir():
        raise Error("需要 /usr/bin/python3 和正在运行的 systemd。")


@contextlib.contextmanager
def locked():
    import fcntl
    with LOCK.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def safe_path(path):
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise Error("拒绝写入符号链接：{}".format(path))


def atomic_write(path, data, mode=0o600):
    safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".po0-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data if isinstance(data, bytes) else data.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def service_state():
    enabled = run("systemctl", "is-enabled", UNIT, ok=(0, 1, 3, 4)).stdout.strip()
    active = run("systemctl", "is-active", UNIT, ok=(0, 3, 4)).stdout.strip()
    if enabled not in ("enabled", "disabled", "not-found"):
        raise Error("服务启用状态为 {}，需先人工核对该服务。".format(enabled))
    if active not in ("active", "inactive", "failed", "unknown"):
        raise Error("服务正在切换状态，请稍后重试：{}".format(active))
    return {"enabled": enabled == "enabled", "active": active == "active"}


def current_table():
    tables = json.loads(run("nft", "-j", "list", "tables").stdout)["nftables"]
    exists = any(v.get("table", {}).get("family") == "ip" and
                 v.get("table", {}).get("name") == TABLE for v in tables)
    return run("nft", "-s", "list", "table", "ip", TABLE).stdout if exists else None


def preflight(c, body):
    require_host()
    interfaces = json.loads(run("ip", "-j", "-4", "address", "show", "dev", c["interface"]).stdout)
    local = {a["local"] for i in interfaces for a in i.get("addr_info", []) if a["family"] == "inet"}
    if c["snat_ip"] not in local:
        raise Error("SNAT 地址 {} 未绑定在 {} 上；Po0 应使用内网地址。".format(c["snat_ip"], c["interface"]))
    ports = {"tcp": set(), "udp": set()}
    for proto, flag in (("tcp", "-lnt"), ("udp", "-lnu")):
        for line in run("ss", "-H", flag).stdout.splitlines():
            fields = line.split()
            if len(fields) >= 5:
                value = fields[3].rsplit(":", 1)[-1]
                if value.isdecimal():
                    ports[proto].add(int(value))
    ssh = os.environ.get("SSH_CONNECTION", "").split()
    if len(ssh) == 4 and ssh[3].isdecimal():
        ports["tcp"].add(int(ssh[3]))
    for r in c["rules"]:
        for proto in protocols(r):
            if r["listen_port"] in ports[proto]:
                raise Error("入口 {}/{} 已被本地服务使用，拒绝覆盖。".format(r["listen_port"], proto))
        route = json.loads(run("ip", "-j", "-4", "route", "get", r["target_ip"]).stdout)
        if not route or route[0].get("type") in ("local", "blackhole", "unreachable", "prohibit"):
            raise Error("目标 {} 的路由不是可转发的单播路由。".format(r["target_ip"]))
    for path in OWNED:
        safe_path(path)
    service_state()
    run("nft", "-c", "-f", "-", data=transaction(body))


def snapshot():
    files = {}
    for path in OWNED:
        safe_path(path)
        if path.exists():
            raw = path.read_bytes()
            files[str(path)] = {"data": base64.b64encode(raw).decode(),
                                "sha256": hashlib.sha256(raw).hexdigest(),
                                "mode": path.stat().st_mode & 0o777}
        else:
            files[str(path)] = None
    return {"version": 1, "files": files, "table": current_table(),
            "ip_forward": IP_FORWARD.read_text().strip(), "service": service_state()}


def read_snapshot(path):
    s = json.loads(path.read_text(encoding="utf-8"))
    if s["version"] != 1 or set(s["files"]) != {str(p) for p in OWNED} or s["ip_forward"] not in ("0", "1"):
        raise Error("不兼容的备份。")
    for info in s["files"].values():
        if info and hashlib.sha256(base64.b64decode(info["data"], validate=True)).hexdigest() != info["sha256"]:
            raise Error("备份校验失败。")
    return s


def save_snapshot():
    safe_path(BACKUPS)
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUPS, 0o700)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = BACKUPS / stamp / "snapshot.json"
    s = snapshot()
    atomic_write(path, json_text(s))
    if read_snapshot(path) != s:
        raise Error("备份回读不一致。")
    print("备份：{}".format(path), flush=True)
    return path


def restore(s):
    run("nft", "-c", "-f", "-", data=transaction(s["table"]))
    # Stop the current unit first: a previous ExecStop may remove its own table.
    run("systemctl", "stop", UNIT, ok=(0, 5))
    run("systemctl", "disable", UNIT, ok=(0, 1, 5))
    for path in OWNED:
        safe_path(path)
        info = s["files"][str(path)]
        if info:
            atomic_write(path, base64.b64decode(info["data"]), info["mode"])
        elif path.exists():
            path.unlink()
    run("systemctl", "daemon-reload")
    if s["service"]["enabled"]:
        run("systemctl", "enable", UNIT)
    if s["service"]["active"]:
        run("systemctl", "start", UNIT)
    run("sysctl", "-q", "-w", "net.ipv4.ip_forward=" + s["ip_forward"])
    run("nft", "-f", "-", data=transaction(s["table"]))


def unit_text():
    command = "/usr/bin/python3 {} boot-load".format(MANAGER)
    return ("[Unit]\nDescription=Po0 IPv4 nftables forwarding\n"
            "After=network-online.target nftables.service\nWants=network-online.target\n\n"
            "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=" + command + "\n"
            "ExecReload=" + command + "\nTimeoutStartSec=90\n\n"
            "[Install]\nWantedBy=multi-user.target\n")


def apply(c):
    body = render(c)
    preflight(c, body)
    backup = save_snapshot()
    source = Path(__file__).read_bytes()
    try:
        atomic_write(RULES, body)
        atomic_write(SYSCTL, "net.ipv4.ip_forward = 1\n", 0o644)
        atomic_write(MANAGER, source, 0o700)
        atomic_write(SERVICE, unit_text(), 0o644)
        atomic_write(DESIRED, json_text(c))
        atomic_write(ACTIVE, json_text(c))
        run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
        run("nft", "-f", "-", data=transaction(body))
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", UNIT)
        run("systemctl", "start", UNIT)
        run("systemctl", "is-active", UNIT)
        run("systemctl", "is-enabled", UNIT)
        run("nft", "list", "table", "ip", TABLE)
        if IP_FORWARD.read_text().strip() != "1":
            raise Error("IPv4 forwarding 验证失败。")
    except BaseException:
        print("应用失败，正在恢复变更前状态……", file=sys.stderr, flush=True)
        try:
            restore(read_snapshot(backup))
        except BaseException as exc:
            print("自动恢复未完成：{}\n请使用备份：{}".format(exc, backup), file=sys.stderr)
        raise
    print("规则已加载，开机自启已启用；这不代表目标服务或 UDP 业务已通过测试。")


def show(c):
    print("网卡：{}  SNAT：{}".format(c["interface"], c["snat_ip"]))
    for r in c["rules"]:
        print("  {:<18} {:>5}/{:<4} -> {}:{}".format(r["name"], r["listen_port"], r["protocol"], r["target_ip"], r["target_port"]))
    if not c["rules"]:
        print("  （空规则；应用后将撤销本表的所有转发）")


def edit(path, name, rule=None):
    c = load(path)
    exists = any(r["name"] == name for r in c["rules"])
    if rule is None and not exists:
        raise Error("未找到规则：{}".format(name))
    c["rules"] = [r for r in c["rules"] if r["name"] != name]
    if rule:
        c["rules"].append(rule)
    validate(c)
    atomic_write(path.with_name(path.name + ".bak"), path.read_bytes())
    atomic_write(path, json_text(c))
    print("待应用配置已保存；运行中的规则未改变。")


def status():
    require_host()
    print(run("systemctl", "is-active", UNIT, ok=(0, 3, 4)).stdout.strip())
    print(run("systemctl", "is-enabled", UNIT, ok=(0, 1, 3, 4)).stdout.strip())
    print("net.ipv4.ip_forward=" + IP_FORWARD.read_text().strip())
    print(current_table() or "专属表不存在。")
    print("NAT 计数器只统计连接的首包，不表示全部业务流量。")


def menu(path):
    while True:
        print("\nPo0 转发管理 | 待应用配置：{}".format(path))
        print("1 查看待应用规则  2 新增/修改  3 删除  4 预览 nft\n5 检查  6 应用并备份  7 运行状态  8 回滚  0 退出")
        try:
            choice = input("> ").strip()
            if choice == "0":
                return
            if choice == "1":
                show(load(path))
            elif choice == "2":
                name = input("规则名称（相同名称会替换）：").strip()
                r = {"name": name, "listen_port": int(input("入口端口：")),
                     "protocol": input("协议 tcp/udp/both [both]：").strip() or "both",
                     "target_ip": input("下一跳 IPv4：").strip(), "target_port": int(input("下一跳端口："))}
                edit(path, name, r)
            elif choice == "3":
                edit(path, input("要删除的规则名称：").strip())
            elif choice == "4":
                print(render(load(path)))
            elif choice == "5":
                c = load(path)
                preflight(c, render(c))
                print("主机、端口和 nft 检查通过；未修改运行配置。")
            elif choice == "6":
                c = load(path)
                show(c)
                if input("输入 APPLY 应用以上完整配置：").strip() == "APPLY":
                    require_host()
                    with locked():
                        apply(c)
            elif choice == "7":
                status()
            elif choice == "8":
                target = Path(input("备份 snapshot.json 完整路径：").strip())
                if input("输入 ROLLBACK 恢复此备份：").strip() == "ROLLBACK":
                    rollback(target)
        except (Error, OSError, ValueError, subprocess.SubprocessError) as exc:
            print("错误：{}".format(exc))


def rollback(path):
    require_host()
    with locked():
        s = read_snapshot(path)
        rescue = save_snapshot()
        restore(s)
        print("已恢复指定备份；回滚前状态另存于：{}".format(rescue))


def main():
    default = DESIRED if Path(__file__).resolve() == MANAGER else Path(__file__).resolve().with_name("po0-forwarding.json")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=default, help="待应用 JSON 配置（放在子命令之前）")
    sub = parser.add_subparsers(dest="command")
    for name in ("menu", "list", "render", "check", "apply", "status", "boot-load"):
        sub.add_parser(name)
    setting = sub.add_parser("set", help="新增或按名称替换待应用规则")
    setting.add_argument("name")
    setting.add_argument("listen_port", type=int)
    setting.add_argument("target_ip")
    setting.add_argument("target_port", type=int)
    setting.add_argument("--protocol", choices=("tcp", "udp", "both"), default="both")
    sub.add_parser("delete").add_argument("name")
    sub.add_parser("rollback").add_argument("snapshot", type=Path)
    args = parser.parse_args()
    cmd, path = args.command or "menu", args.config
    if cmd == "menu":
        menu(path)
    elif cmd == "status":
        status()
    elif cmd == "boot-load":
        # Called by systemd while apply holds the management lock; do not lock again.
        require_host()
        run("nft", "-c", "-f", "-", data=transaction(RULES.read_text()))
        run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
        run("nft", "-f", "-", data=transaction(RULES.read_text()))
    elif cmd == "rollback":
        rollback(args.snapshot)
    elif cmd == "set":
        edit(path, args.name, {"name": args.name, "listen_port": args.listen_port,
                              "target_ip": args.target_ip, "target_port": args.target_port, "protocol": args.protocol})
    elif cmd == "delete":
        edit(path, args.name)
    elif cmd == "list":
        show(load(path))
    elif cmd == "render":
        print(render(load(path)), end="")
    elif cmd == "check":
        c = load(path)
        preflight(c, render(c))
        print("检查通过；未修改运行配置。")
    elif cmd == "apply":
        require_host()
        with locked():
            apply(load(path))


if __name__ == "__main__":
    # Preserve immediate rollback on Ctrl-C/SIGTERM during apply.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        main()
    except (Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("错误：{}".format(exc), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("已中止。", file=sys.stderr)
        sys.exit(130)
