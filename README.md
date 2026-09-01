# Wukong Dashboard UI

这是悟空质量价值生产后台的公开源码工程。仓库只保存可复用的 UI、服务端鉴权网关、数据契约、脱敏 fixture 和安全测试；正式数据仍留在本机，由只读服务在登录后提供。此目录当前只是本地源码包，尚未创建 GitHub 远端、推送或部署。

## 安全边界

- 默认所有者账号为 `liyilin`。每位有关人士应有独立账号，所有者部署时为每个账号另行输入新密码。
- 明文密码不写入代码、命令行、Git 或日志。使用 `scripts/make_password_hash.py` 离线生成 PBKDF2-SHA256 哈希，并将账号—哈希映射作为部署 Secret `WUKONG_DASHBOARD_USERS_JSON` 保存。
- `WUKONG_SESSION_SECRET` 也必须作为部署 Secret 注入；不要把 `.env`、哈希或 Tunnel 凭据放进仓库。
- 网关只监听 `127.0.0.1`，Cloudflare Tunnel 只转发到这个回环地址；不运行 GitHub Pages，也不暴露可绕过鉴权的源站地址。
- 登录后的页面、静态资源、API、JSON、CSV、PDF 和图片均经过同一个服务端会话检查。正式账本可通过受限的只读审计 API 查看，但数据库文件扩展名始终拒绝直接下载；部署密钥、Tunnel 凭据及其他系统凭据也绝不作为站点资源提供。
- 正式数据路径由启动参数指定，真实账本、持仓、订单、调仓预告、CSV/JSON、PDF/图片仍保留在本机并在登录后只读展示，源码包不复制它们。
- 撤销某人的访问时，从 `WUKONG_DASHBOARD_USERS_JSON` Secret 中移除其账号并重启网关。内存会话随重启清空；不共享账号即可精确撤销。

## 本机启动

在部署主机上设置会话 Secret，并使用推荐的多账号 Secret（内容只保存于部署环境）：

```powershell
$env:WUKONG_DASHBOARD_USERS_JSON = '{"liyilin":"<所有者哈希>","reviewer":"<审阅者哈希>"}'
$env:WUKONG_SESSION_SECRET = '<随机生成的长字符串>'
```

初始单账号部署可继续使用 `WUKONG_DASHBOARD_USERNAME` 与 `WUKONG_DASHBOARD_PASSWORD_HASH`，但不适合向多人共享。

然后启动只读网关。`--dashboard-root` 应指向当前项目的 `dashboard_local`，而不是复制出来的数据库目录：

```powershell
.scripts\run_gateway.ps1 -DashboardRoot 'C:\Users\liyil\Desktop\WUKONG\dashboard_local' -Origin 'https://你的域名'
```

上例默认服务源码包中的脱敏 UI。若要直接展示当前完整本地后台，请显式指定其 UI 根目录：

```powershell
.scripts\run_gateway.ps1 -DashboardRoot 'C:\Users\liyil\Desktop\WUKONG\dashboard_local' -UiRoot 'C:\Users\liyil\Desktop\WUKONG\dashboard_local' -Origin 'https://你的域名'
```

生产环境不应使用 `-InsecureLocalhost`。这个选项只用于本机测试，它会关闭 Cookie 的 Secure 标志。

## 正式账本审计 API

已登录用户可读取 `/api/ledger/tables` 获取正式账本的白名单表与行数，再通过 `/api/ledger/table/<表名>?limit=500&offset=0` 分页查看记录。只允许当前正式账本 `wukong_shadow.db` 中的 `data_snapshot`、`ledger_meta`、`nav_daily`、`position_daily`、`trade_ledger` 表；没有 SQL 参数入口，也没有下载数据库文件的路由。

## 密码哈希

```powershell
python .\scripts\make_password_hash.py
```

脚本通过隐藏输入读取密码，只输出哈希；不要把输出粘贴到本 README 或任何公开文件。

## Cloudflare Tunnel

复制 `cloudflared/config.example.yml` 到 Cloudflare 的本机配置目录，填写 Tunnel UUID、域名和凭据文件路径。Ingress 的唯一服务目标应是：

```text
http://127.0.0.1:8766
```

不要把生产后台部署为普通 GitHub Pages。`scripts/install_gateway_boot_task.ps1` 只提供稳定名称的开机任务模板：`WukongPrivateDashboardGateway` 与 `WukongPrivateDashboardTunnel`。执行前先确认 `cloudflared` 已安装、凭据文件权限正确，并检查现有任务；脚本不会修改既有每日正式更新任务。

## 测试与公开包门禁

```powershell
python .\scripts\scan_public_tree.py
python -m unittest discover -s tests -v
```

扫描器使用显式白名单，只允许 UI、网关、脚本、Tunnel 示例、Schema、脱敏 fixture、测试、README、许可证和 Git 忽略文件。发现数据库、真实报表、持仓/订单/预告文件、凭据或疑似密钥后返回失败。

首次创建公开 GitHub 仓库或推送前，必须人工复核扫描器输出的文件白名单，并单独确认远端仓库名 `wukong-dashboard-ui`。
