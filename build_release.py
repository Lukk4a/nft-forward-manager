"""Build a reproducible offline tarball and a pinned mirror bootstrap."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent
FILES = ("po0-nft-forward.py", "po0-forwarding.example.json", "install.py", "README.md", "VERSION")
REPO = "Lukk4a/nft-forward-manager"


def build():
    version = (ROOT / "VERSION").read_text().strip()
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    name = "nft-forward-manager-{}.tar.gz".format(version)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name_in in FILES:
            data = (ROOT / name_in).read_bytes()
            entry = tarfile.TarInfo(name_in)
            entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
            archive.addfile(entry, io.BytesIO(data))
    package = dist / name
    with package.open("wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0) as zipped:
            zipped.write(buffer.getvalue())
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    url = "https://github.com/{}/releases/download/v{}/{}".format(REPO, version, name)
    bootstrap = '''#!/bin/sh
set -eu
umask 077
if [ "$(id -u)" -ne 0 ]; then echo "请以 root 运行。" >&2; exit 1; fi
for cmd in curl python3 sha256sum tar; do
  command -v "$cmd" >/dev/null || { echo "缺少依赖：$cmd" >&2; exit 1; }
done
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
asset="$work/package.tar.gz"
original='__URL__'
expected='__HASH__'
downloaded=0
# Set NFT_FORWARD_DOWNLOAD_URL to your own complete HTTPS asset URL if needed.
if [ -n "${NFT_FORWARD_DOWNLOAD_URL:-}" ]; then
  candidates="$NFT_FORWARD_DOWNLOAD_URL"
else
  candidates="https://ghfast.top/$original https://gh-proxy.com/$original"
fi
for source in $candidates; do
  case "$source" in https://*) ;; *) echo "只支持 HTTPS 下载地址。" >&2; exit 1 ;; esac
  echo "下载：$source"
  if curl --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 90 --retry 1 "$source" -o "$asset"; then
    if printf '%s  %s\\n' "$expected" "$asset" | sha256sum -c -; then
      downloaded=1
      break
    fi
  fi
done
if [ "$downloaded" -ne 1 ]; then echo "下载或校验失败，未执行安装。" >&2; exit 1; fi
tar -xzf "$asset" -C "$work"
python3 "$work/install.py" "$@"
'''.replace("__URL__", url).replace("__HASH__", digest)
    installer = dist / "install.sh"
    installer.write_text(bootstrap, encoding="utf-8", newline="\n")
    installer_hash = hashlib.sha256(installer.read_bytes()).hexdigest()
    (dist / "SHA256SUMS").write_text("{}  {}\n{}  install.sh\n".format(digest, name, installer_hash), encoding="ascii")
    print((dist / "SHA256SUMS").read_text(), end="")


if __name__ == "__main__":
    build()
