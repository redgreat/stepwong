# AGENTS.md

本文件面向 coding agent，描述本仓库的结构、运行机制与维护约定。

## 项目概述

stepwong 通过 Zepp Life（原小米运动/华米）开放接口修改账号步数，步数经 Zepp Life 服务端同步到已绑定的第三方平台（微信运动、支付宝运动等）。核心逻辑为单个 Python 脚本，由 GitHub Actions 定时执行。

## 仓库结构

| 文件 | 说明 |
|------|------|
| `main.py` | 主程序：登录 Zepp 账号、提交步数、Token 缓存、pushplus 推送 |
| `requirements.txt` | Python 依赖（requests / pytz / pycryptodome） |
| `.github/workflows/run.yml` | 主 workflow「刷步数」：定时触发，安装 Python 并执行 `main.py` |
| `.github/workflows/cron.yml` | 「Random Cron」：run.yml 成功后触发，随机改写 run.yml 的 cron 分钟数并 push 回仓库 |
| `cron_convert.sh` | cron.yml 使用的 bash 函数库（时区换算、改写 cron、写执行日志） |
| `cron_change_time` | 自动生成的执行日志，记录当前/下次 cron 时间，由 cron.yml 提交，**勿手动编辑** |

## 运行机制

1. `run.yml` 按 cron 触发（UTC 时间），`ubuntu-latest` 上 `pip3 install requests pytz pycryptodome` 后执行 `python3 main.py`。
2. `cron.yml` 监听 run.yml 的 `workflow_run`，成功后 source `cron_convert.sh`，用 `persist_execute_log` 随机化 cron 分钟、更新 `cron_change_time`，再以 `cronwong` 身份 commit + push。这是为了让 schedule 的触发时间每次不同（降低 GitHub 暂停不活跃 schedule 的概率），**修改 run.yml 的 cron 行时不要破坏 `- cron: 'M H * * *'` 的格式**，否则 `cron_convert.sh` 的 sed 正则会失效。
3. `main.py` 主流程（`execute()`）：
   - 从环境变量 `CONFIG`（JSON）读取账号/步数配置，`AES_KEY` 控制 token 缓存。
   - 每个账号走 `MiMotionRunner.login()`：`api-user.zepp.com/v2/registrations/tokens`（AES-128-CBC 加密登录参数）→ 302 跳转拿 access token → `account.huami.com/v2/client/login` 换 `login_token` → `account-cn.huami.com/.../app_tokens` 换 `app_token`。
   - `login_and_post_step()` 按当前北京时间占 22:00 的比例缩放步数上下限（`get_min_max_by_time`），在区间内随机取值，POST 到 `api-mifit-cn.huami.com/v1/data/band_data.json`。
   - 提交前会用 `get_user_device_id()` 查询账号绑定的真实手环/手表设备 ID 作为 `last_deviceid`（查不到则回退到写死的 `DA932FFFFE8816E7`）——华米对从未绑定过设备的账号会校验该字段，直接沿用旧逻辑会被判定为无效提交，表现为接口返回 success 但第三方不同步。
   - 多账号默认串行执行、间隔 `SLEEP_GAP` 秒；`USE_CONCURRENT=True` 时并发（注意 `executor.map` 返回的是迭代器，没有真正并发收益，属历史遗留）。
   - 配置了 `AES_KEY`（16 字节）时，登录 token 加密存到 `encrypted_tokens.data` 复用；未配置则每次全量登录。

## 配置

GitHub Secrets：

| Secret | 说明 |
|--------|------|
| `CONFIG` | JSON：`USER`/`PWD`（多账号用 `#` 分隔）、`MIN_STEP`、`MAX_STEP`、`SLEEP_GAP`（秒）、`USE_CONCURRENT`、`PUSH_PLUS_TOKEN`、`PUSH_PLUS_HOUR`、`PUSH_PLUS_MAX` |
| `AES_KEY` | 可选，16 字节字符串，启用 token 加密缓存 |
| `STEP_PAT` | cron.yml 里 checkout 用的 PAT（需要能 push 回仓库） |

Repository variable：`CRON_HOURS`（可选），cron.yml 用来覆盖随机化后的小时列表。

## 本地运行与验证

```bash
pip install -r requirements.txt
export CONFIG='{"USER":"13800138000","PWD":"xxx","MIN_STEP":18000,"MAX_STEP":25000,"SLEEP_GAP":5}'
export AES_KEY='1234567890abcdef'   # 可选
python3 main.py
```

- Python 版本：当前 workflow 用 3.12，脚本无版本敏感语法，3.9+ 基本都能跑。
- 无测试框架；验证方式为本地跑通登录 + 提交步数，或直接 `workflow_dispatch` 触发看日志。
- `main.py` 会打印每个账号的执行日志（含脱敏账号、加密后参数长度、接口返回 message），排查先看 Actions 日志。

## 维护约定

- 不要提交 `encrypted_tokens.data`、任何包含真实账号密码的配置或 token。
- `cron_change_time` 由自动化生成，手动改它没有意义。
- cron.yml 的自动提交用 `git config user.name cronwong`，commit message 格式为 `[时间] random cron trigger by <event>`。
- 修改登录/上报接口相关代码前，先确认 Zepp 接口现状（见 README 引用的 hanximeng/Zepp_API 实现），本脚本模拟 MiFit 6.14.0 Android 客户端。
