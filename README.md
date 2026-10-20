# nft-forward-manager

IPv4 TCP/UDP nftables 端口转发管理工具，提供中文菜单和命令行。Python 3.9+，只依赖标准库。沿用 `ip po0_forwarding` 专属表及 `po0-forwarding.service` 名称，兼容已有的 Po0 转发部署。

公开仓库和 Release **不包含任何实际服务器地址、转发配置或登录信息**。示例与测试只使用文档保留地址。

## GitHub 无法直连时安装

版本发布在 [GitHub Releases](https://github.com/Lukk4a/nft-forward-manager/releases)。Po0 不需要安装 Git 或访问 GitHub API。安装引导优先使用 `ghfast.top`，失败时改用 `gh-proxy.com`，下载完整离线包并校验内置的 SHA-256。

```sh
curl --fail --location --connect-timeout 10 --max-time 60 \
  https://ghfast.top/https://github.com/Lukk4a/nft-forward-manager/releases/download/v1.0.0/install.sh \
  -o /root/install-nft-forward.sh
```

从该版本 Release 页面 `SHA256SUMS` 核对 `install.sh` 的摘要后，再执行：

```sh
bash /root/install-nft-forward.sh
```

若第一个地址不可达，将下载地址开头的 `https://ghfast.top/` 换为 `https://gh-proxy.com/`。这两个域名是第三方下载加速服务；实际能否访问取决于服务器网络，不将本机测试表述为 Po0 实测。

安装后使用：

```sh
nft-forward
```

安装仅写入 `/opt/nft-forward-manager/releases/<版本>/` 及 `/usr/local/bin/nft-forward`。安装或更新**不会应用转发规则，也不会重启现有转发服务**。安装成功后，程序运行、配置和开机加载均不依赖 GitHub 或加速站点。

需要自行提供 Python 3.9+、nftables、iproute2、procps、systemd。下载安装另需 curl、tar、sha256sum，脚本不自动安装系统软件包。

## 保留实际配置

配置只保存在服务器本地的 `/etc/po0-forwarding/desired.json`。已有文件在安装/更新时保留；若此前已使用该工具的 `active.json`，首次安装会从它初始化待应用配置。

如果服务器尚无该 JSON（例如此前只部署了 `.nft` 规则），可在首次安装时指定已有的本地配置：

```sh
bash /root/install-nft-forward.sh --config /root/po0-forwarding.json
```

Po0 的专用 JSON 使用此前私下保存的配置，**不要提交到公开仓库或 Release**。仅有 `.nft` 文件时，安装不会猜测、导入或覆盖它；现有转发继续运行，准备好对应 JSON 后再应用。

全新部署可以参考 `po0-forwarding.example.json`，设置网卡、网卡实际绑定的 SNAT IPv4、受保护端口和规则。示例 `rules` 为空；不要用空配置覆盖已有转发。

规则格式：

```json
{
  "interface": "eth0",
  "snat_ip": "192.0.2.10",
  "protected_tcp_ports": [22],
  "rules": [
    {"name": "example", "listen_port": 60001, "protocol": "both", "target_ip": "198.51.100.10", "target_port": 8388}
  ]
}
```

## 管理规则

```sh
nft-forward list
nft-forward set example 60001 198.51.100.10 8388 --protocol both
nft-forward delete example
nft-forward render
nft-forward check
nft-forward apply
nft-forward status
nft-forward rollback /var/backups/po0-forwarding/实际备份时间/snapshot.json
```

新增、修改、删除只修改待应用 JSON，`apply` 才会替换专属表中的完整规则集。中文菜单会在应用前显示规则并要求输入 `APPLY`；命令行 `apply` 直接执行。

应用前检查网卡、SNAT 地址、路由、监听端口、SSH 会话端口和 `nft -c`。保存专属表、相关配置及服务状态的备份后，才执行变更。普通失败或中断会尝试恢复；提供手动回滚，回滚前也会保存当前状态。断电或 SIGKILL 无法保证即时自动恢复。

应用会将管理程序保存至 `/usr/local/sbin/po0-nft-manager.py`，生成 `/etc/nftables.d/po0-forwarding.nft`、sysctl 配置及 `po0-forwarding.service`，并启用该服务开机加载。原 `/usr/local/sbin/po0-nft-forward` 文件保留以便恢复旧配置，但新单元使用新程序。

## 自有下载源和完全离线安装

将同一版本完整的 `.tar.gz` 放到自己的 HTTPS 下载地址，指定地址后仍按固定摘要校验：

```sh
NFT_FORWARD_DOWNLOAD_URL=https://downloads.example.com/nft-forward-manager-1.0.0.tar.gz \
  bash /root/install-nft-forward.sh
```

或将 Release 包通过 SSH 等方式传到服务器，核对摘要后解压安装，整个安装过程无需网络：

```sh
tar -xzf nft-forward-manager-1.0.0.tar.gz
python3 install.py --config /root/po0-forwarding.json
```

## 验证范围

- 只管理专属表，不执行全局 `flush ruleset`，不修改其他防火墙表、SSH 或其他节点。
- 只处理指定网卡入站、本机目标地址及指定端口的 IPv4 PREROUTING DNAT/SNAT；不配置 IPv6 或本机 OUTPUT 转发。
- 现有过滤链或云安全组仍可能丢弃流量，脚本不改变其策略。新增中转目标需要对应节点已经具备转发能力。
- 已有 conntrack 条目可能继续走旧目标；不会自动清空连接。应由外部客户端发起新连接验证，UDP 需实际请求和回复。
- NAT 计数器只统计连接首包，不能当作业务总流量或往返成功证明。
- 全局 nftables 重载若清空所有表，需要重新加载专属服务。

## 开发和发布

```sh
python3 -B -m unittest discover -p 'test_*.py' -v
python3 build_release.py
```

`dist/` 输出可重复构建的离线包、固定版本下载引导 `install.sh` 以及 `SHA256SUMS`。测试使用模拟主机状态，不改变本机或服务器防火墙；真实内核规则由目标机 `check` 验证。

参考：[nftables 官方手册](https://netfilter.org/projects/nftables/manpage.html)、[GH-Proxy 的下载地址格式](https://gh-proxy.com/docs/quick-start)。
