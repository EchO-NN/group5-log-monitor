# 部署与操作

## 组件分工

VM8 运行 Wazuh 4.14.9、DFIR-IRIS 2.4.29 和监控转发服务。A 电脑运行采集调度与 AI 调查服务。VM9 提供 Prometheus，Node Exporter 暴露受监控主机指标。项目沿用现有平台，公开版使用可配置的 SSH 别名代替个人虚拟化管理脚本。

## 主机连接

复制 `configs/hosts.example.json` 为 `configs/hosts.local.json`。在本机 `~/.ssh/config` 为 `lab-vm2` 至 `lab-vm9` 配置实际地址、账号和密钥路径，提前登记主机公钥。执行器固定使用 `BatchMode=yes` 和 `StrictHostKeyChecking=yes`。VM1 与 Windows 宿主机不在公开版采集范围内。

Agent 的主机角色、实验地址与查询能力位于 `scripts/monitoring/agent_policy.json`。重用到其他拓扑时，同步修改该文件和 `performance.py` 的 `TARGETS`。文件调查在本机的允许目录默认是 `/opt/group5-log-monitor`。

远端查询账号需能读取 journal、audit 以及相应应用日志。项目不在远端执行模型提供的 Shell；授权查询由固定 Python 程序完成。账号权限由实验环境管理员配置。

## VM8 监控转发

将 `scripts/monitoring/` 下的 Python 和 JSON 文件部署到 `/usr/local/lib/group5-monitor/`，将 `configs/bridge.example.json` 保存为 `/etc/group5-monitor/config.json`。填写 IRIS 的 HTTPS 地址、现有 Case 和 Customer 编号、可信 CA 路径。将实际 IRIS API 密钥保存为仓库外的 `iris.local.json`，内容为单个 `api_key` 字段，权限设为 `0600`。

Wazuh Agent 将认证、Auditd 和应用日志传给 VM8；VM2 通过 TCP Syslog 514 上报网关日志。VM8 启用 JSON 原始日志归档。`configs/wazuh/group5_rules.xml` 包含网关拒绝和备份校验失败规则，部署前检查规则编号是否与现有规则重复。

转发服务读取 `/var/ossec/logs/alerts`、`/var/ossec/logs/archives` 和管理采集收件目录。其 SQLite 状态库和证据目录位于 `/var/lib/group5-monitor`。使用 `configs/systemd/group5-monitor.service` 管理服务。

## A 电脑上的采集与 AI

将项目放到 `/opt/group5-log-monitor`，按实际路径调整 systemd 单元。采集器每轮读取上次成功投递后的游标，投递到 VM8 后才推进游标；VM9 离线时记录 unavailable，其他主机继续采集。

```bash
python3 scripts/collect-monitor-remotes.py --roles 3 4 5 6 7 9
```

模型配置使用 `configs/summary-provider.example.json`。填写提供商的 Responses API 地址、模型名、推理强度和仓库外密钥文件路径。课堂环境配置为 PackyAPI 的 `gpt-6.1-sol`、`xhigh`。提供商地址来自本地配置，公开项目不绑定个人账号。

将示例保存为 `/etc/group5-monitor/summary-provider.local.json`，实际密钥保存在其 `credential_file` 指向的文件中，权限 `0600`。安装用户级 `group5-summary.service` 后按需启动：

```bash
systemctl --user start group5-summary.service
systemctl --user stop group5-summary.service
```

`group5-collector.timer` 和 `group5-collector.service` 是用户级定时采集模板；`group5-monitor.service` 是 VM8 系统服务模板。后台 AI 停止不会删除已有案件。

## 一轮演练

攻击开始前运行 `./监控自动化.sh begin --label "第五组正式演练"`。演练期间查看 Wazuh 原始告警和 IRIS Alerts。结束时执行 `finish`，程序等待在途日志后启动调查。`ai` 显示当前工具、任务和已执行动作；最终结果在本轮 Case 中查看。

每轮对应独立案件。`finish` 冻结的是本轮分析范围，时间线使用原始事件时间。调查结束后按 Summary、Timeline、Evidence、Tasks 的顺序复核。
