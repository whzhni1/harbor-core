
# harbor-core

[**English**](./README.md) | 简体中文

> 本仓库是 Harbor File Pro 的 **Rust 内核**，自身即 Web 服务器。装好二进制、起一个进程，浏览器访问 `http://<设备>:9700/` 就是完整应用：前端页面、`/api/v1/*`、`/io` 流式读写、分片上传、SSH 远程设备、账号与 2FA 全在这一个进程里。
> 需要 OpenWrt 服务管理、UCI 配置、日志、内核安装/在线更新与防火墙放行时，安装 LuCI 面板 **[luci-app-harbor-file-pro](https://github.com/whzhni1/luci-app-harbor-file-pro)**。

Harbor File Pro 把文件管理推向了新高度。原版 Harbor File 做到了能用，Harbor File Pro 做到了好用、功能与操作体验以及视觉体验精细到头发丝。

> 无大小限制的文本/Hex 编辑 · 多终端保活与远程设备互连 · 深度解压/压缩增强 · 任务栏多窗口 · 收藏夹 · 权限可视化 · 流式加载 · 断点续传 · 完美适配移动端。

---

## 快速开始

### 方式一：Release 二进制

从 [Releases](https://github.com/whzhni1/harbor-core/releases) 下载对应架构的 `harbor-core-<version>-<triple>.tar.gz`，解压后：

```sh
# 首次初始化账号（本机执行，无回显输入用户名和两行密码）
./harbor-core init-auth -s /etc/harbor

# 启动服务
./harbor-core serve \
    --config /etc/config/harbor_file_pro \
    --state-dir /etc/harbor \
    --listen 0.0.0.0:9700
```

浏览器访问 `http://<设备>:9700/`，会跳转到 `/login`，使用 `init-auth` 设置的账号登录。

> 初始用户名和密码不能从网络设置，只能本机通过 `init-auth` 初始化；重置同样只能本机执行 `reset-auth`。

### 方式二：OpenWrt 用户（推荐配合 LuCI 面板）

1. 安装 **[luci-app-harbor-file-pro](https://github.com/whzhni1/luci-app-harbor-file-pro)**；
2. 在 LuCI 的 **系统 → Harbor File Pro → Overview** 中安装/更新内核；
3. 完成初始账号设置；
4. 通过 `http://<设备IP>:9700` 使用文件管理功能。

### 方式三：从源码构建

```sh
# assets/ 是静态前端源目录，build.rs 将其嵌入二进制
cargo build --release

./target/release/harbor-core serve \
    --config /etc/config/harbor_file_pro \
    --state-dir /etc/harbor \
    --listen 0.0.0.0:9700
```

---

## 界面截图

<details>
<summary>展开查看主界面、Hex 编辑器、权限管理、远程设备、移动端截图</summary>

<p align="center">
  <img src="https://github.com/user-attachments/assets/bf021bb1-7708-4646-8543-0b0190978b77" width="720" alt="Harbor File Pro 主界面">
  <br>
  <sub>主界面：文件管理、窗口多开与任务栏</sub>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/84caffb7-326d-4bb5-befc-7549205cf562" width="720" alt="十六进制编辑器">
  <br>
  <sub>十六进制编辑器：Hex/ASCII 双视图、正则查找替换</sub>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/82ab9cd8-d435-47ae-8b65-6725ef53336b" width="720" alt="权限管理与个性化设置">
  <br>
  <sub>权限可视化、递归权限与个性化设置</sub>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/e96eeafc-7322-4e32-ad33-efc0ba190d1a" width="720" alt="远程设备互连与多终端">
  <br>
  <sub>远程设备互连、跨设备传输与多终端保活</sub>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/75592519-6025-4e92-907b-95d8479bbf6f" width="300" alt="移动端界面">
  <img src="https://github.com/user-attachments/assets/9ca1072c-a882-4302-940e-8f1325451ba6" width="300" alt="移动端桌面模式">
  <br>
  <sub>移动端触屏适配与手机浏览器桌面模式</sub>
</p>

</details>

> LuCI 管理面板截图请见 [luci-app-harbor-file-pro](https://github.com/whzhni1/luci-app-harbor-file-pro)。

---

## 核心功能

### 文件管理

- 桌面级窗口交互：多开、自由缩放/最大化/最小化、窗口尺寸记忆；
- 任务栏可在桌面底部左/中/右任意位置呼出，闲置 3 秒自动隐藏；窗口切换逻辑贴合 Windows；
- 收藏夹：收藏当前路径，支持命名、新建文件夹、移动、删除；
- 地址栏点击空白区域直接输入路径，桌面/移动端均可；
- 目录上传与统计：支持直接上传整个文件夹；属性页显示目录占用大小、子目录数量、文件数量；
- 粘贴冲突三选一：同名文件可选 **覆盖 / 重命名（自动加序号）/ 跳过**；
- 覆盖文件时保留原始权限；支持直接输入重命名、替换文件；移动/复制时可手动输入目标路径。

### 十六进制编辑器：1TB 文件不卡，浏览器不冻结

原版 Hex 只能"看"，且无法打开大文件。Pro 把 Hex 编辑器做成了**专业级修改工具**。

- **大文件零压力**：打开 **1TB 或 10TB 文件与 1KB 文件同样流畅**，流式加载，大二进制文件操作绝对不触发 OOM，浏览器不卡死；
- **正则查找替换**：支持正则表达式、区分大小写，显示匹配位置与数量，结果高亮，支持 Replace / Replace All；
- **双视图同步**：Hex 视图（00–0F）与 ASCII 视图同时显示，点击任一侧另一侧同步高亮；
- **撤销 / 重做 + 异常恢复**：意外关闭后可恢复未保存修改。

### 文本编辑器：不丢数据，代码高亮

- **无文件大小限制**：流式加载，文本文件流畅，浏览器不冻结；
- **专业级搜索**：大小写敏感、匹配计数、高亮定位、Replace / Replace All / 上下个；
- **数据安全**：撤销/重做，意外关闭自动询问恢复未保存修改；
- **代码高亮**：Prism 语法高亮，自动清理 U+200B 零宽空格。

### 解压与压缩：能力全面碾压原版

原版解压能力非常基础，Pro 在**格式支持、路径控制、冲突处理、批量操作**四个维度全面扩展：

- **解压增强**：可像 WinRAR 一样预览文件，选择指定文件解压，**解压前可选择目标路径**（面包屑跳转或手动输入）；同名文件提示覆盖，绝不静默覆盖或直接失败；长路径下保留空白可点击区域，防止无法输入路径；
- **压缩增强**：**压缩时可选择输出路径**；目标文件已存在时提示覆盖；**修复覆盖文件夹时丢失已有文件的问题**，支持解压更多格式；
- 冲突处理统一见「文件管理」中的粘贴冲突三选一机制。

### 文件操作与权限管理

原版无权限编辑，Pro 增加了**权限编辑、递归范围控制**和**可视化双模式**。

- **权限可视化**：文件/文件夹属性页直接勾选读/写/执行，也可手动输入 `755` 等数字；
- **高级递归权限**：可区分"仅对文件生效"或"对目录及文件生效"，只改普通文件而保持目录权限不变；
- 其余操作细节（覆盖保留权限、重命名、替换文件、移动/复制目标路径）见「文件管理」。

### 远程设备与多终端

远程设备的所有能力都在本进程内通过 **russh + SFTP** 完成，**不再 fork 本机 `ssh`/`sshpass`，也不经过 LuCI / ubus**。

- **文件枢纽中心**：对远程设备进行操作与本机操作完全一致；
- **跨设备互连**：将远程 OpenWrt 设备的文件系统当作本地目录操作，支持跨设备复制/粘贴/移动/剪切；
- **终端多开与保活**：支持同时打开多个终端（本地/远程），最小化窗口保留连接（点击 X 才销毁）；支持一键刷新重连，重连回放；
- **首次连接 TOFU**：批量探测显示 `SHA256:<b64>`，确认后写入 `host_key`；
- **多设备适配**：手机浏览器、手机浏览器桌面模式、HTTP / HTTPS、触摸设备与输入法组合操作；
- **依赖安装**：远端支持 `apk`、`opkg`、`apt`、`dnf`、`yum`、`pacman` 命令分支，后台任务执行。

### 桌面级窗口与主题

- Win11 同款主题：深色/浅色，支持自动根据浏览器切换，支持自定义透明度和磨砂效果；
- 屏幕铺满开关；错误提示为 Windows 风格弹窗；
- 内置壁纸，以及在线壁纸；UApiPro、Bing、Openverse 图片由浏览器直接加载，不下载到设备；
- 登录页可单独选择是否应用当前壁纸。

### 移动端触屏适配

- 单击打开，长按出菜单；长按拖拽移动，支持多选批量拖拽；
- 拖到页面边缘自动滚动；勾选文件时页面自动滚动到顶部/底部；
- 手机浏览器设置为桌面模式同样做了适配。

---

## 运行模型

```text
       浏览器
         │  HTTP :9700（原生 HTTP；HTTPS 需自行配置前置代理）
         ▼
┌────────────────────────── harbor-core 进程 ──────────────────────────┐
│ 静态资源（内嵌 index.html / js / css / icons）                        │
│ /login · /api/v1/*（66 个端点）· /io（Range 流式读写）                 │
│ 分片上传 session · 传输任务表 · 并发/超时/背压中间件                    │
│ SSH 远程设备（russh + SFTP，直连，不经 ubus）                           │
│ 账号：口令 + TOTP + Cookie 会话；偏好、书签、壁纸                      │
└──────────────────────────────────────────────────────────────────────┘
         │                         │                        │
   /etc/config/harbor_file_pro  /etc/harbor（state）   系统工具（按需安装）
```

| 角色 | 负责 |
| --- | --- |
| `harbor-core` | 页面 + 全部接口 + 传输层 + 账号/会话/2FA + 偏好/壁纸 + 远程设备 |
| LuCI 插件（可选） | 配置外壳：UCI 表单、重置口令按钮、打开 `:9700` 的入口；不含前端资源与后端业务代码 |
| 系统工具（按需） | 归档、缩略图、SSH 及包安装依赖外部程序 |

---

### 传输与背压

| 选项 | 默认 | 作用 |
| --- | --- | --- |
| `max_connections` | 16 | 并发请求上限，超出直接 `503 queue_full` |
| `max_transfers` | 4 | 同时在跑的传输数，超出 `503 queue_full` |
| `request_timeout` | 60 | 单个请求总时限 |
| `body_idle_timeout` | 30 | 上传分片 30 秒没数据即断开 |
| `chunk_size` / `chunk_limit` | 1 MiB / 16 MiB | 分片大小与单片上限 |
| `upload_session_hours` | 24 | 未完成 session 的保留时长，启动时清理更早的 |
| `workers` | 0（= min(cpus, 4)） | Tokio 工作线程数；单核设备设 1 反而更快 |

> 完整 UCI 配置项、LuCI 面板管理项与保存后的自动动作，见 [luci-app-harbor-file-pro](https://github.com/whzhni1/luci-app-harbor-file-pro) 的 README。

---

## 账号、会话与安全

- **首次初始化 / 重置**：初始用户名和密码不能从网络设置，必须本机执行 `init-auth`（无回显）；重置只能本机执行 `reset-auth`；
- **系统目录授权**：读取或写入系统目录前需重新输入密码（启用 TOTP 还需动态验证码），默认 15 分钟无操作后失效；
- **会话三参数**：`session_ttl`（绝对上限，不可滑动延长）/ `session_idle`（空闲超时，`0` 关闭）/ `session_sliding`（活跃时刷新 Cookie 空闲寿命，不改 token）；
- **失效机制**：daemon 重启轮换 `auth.key` 使旧 token 失效；`/logout` 立即从服务端 session 表移除；任何 401 前端统一跳 `/login?expired=1`；
- **登录限速**：按客户端 IP 统计失败次数，第 3 次失败锁 30 秒，累计第 4、7、10 次进入 60 秒 / 180 秒 / 进程内不再自动解锁档位；
- **口令与密钥存储**：口令 PBKDF2-SHA256 单向哈希（`<state-dir>/password` 0600）；SSH 密码与 TOTP 密钥经 ChaCha20-Poly1305 加密（`<state-dir>/secrets.enc` 0600）；UCI 不保存远程密码；
- **认证方式**：只接受 HttpOnly Cookie，不接受 URL token 或 Bearer token；TOTP 使用 RFC 6238（SHA1 / 6 位 / 30 秒，前后各容一格时钟偏差）。
---
## 按需依赖

以下依赖都是"要用某功能才装"，不是运行前提：

| 功能 | 依赖 |
| --- | --- |
| 压缩/解压 | `tar`（含 `xz`/`bzip2` 支持）、`gzip`；7z 走 `bsdtar` 或 `7z` |
| 缩略图 |  `graphicsmagick`（缩略图） |
| 内置终端 | 进程内 PTY；本机仍需登录 shell，远程经 SSH 交互会话；WebSocket 同源直连并支持断线回放 |
| 远程设备 | 进程内 russh + SFTP；远端需要 sftp 子系统（通常 `openssh-sftp-server` 或 `internal-sftp`） |
| 壁纸自定义 URL | `curl` → `wget` → `uclient-fetch` 任一 |

本机安装只支持以 root 直接调用 `opkg`/`apk`；远端还识别 `apt`/`dnf`/`yum`/`pacman`，并可使用非交互 `sudo`。工具名、包名会先校验。

---


## 相关仓库

- **harbor-core**（本仓库，Rust 内核）：
  <https://github.com/whzhni1/harbor-core>
- **luci-app-harbor-file-pro**（OpenWrt LuCI 管理面板）：
  <https://github.com/whzhni1/luci-app-harbor-file-pro>

---

## 许可与致谢

Harbor File Pro V2（本仓库，Rust 内核）由 Harbor File Pro V1.x（ucode 版）重写而来，V1.x 则发展自 [destan19/luci-app-harbor-file](https://github.com/destan19/luci-app-harbor-file)。感谢原作者打下的出色基础。

> 始于 Harbor File，超越 Harbor File —— 这就是 Harbor File Pro。
