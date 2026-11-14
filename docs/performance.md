# VM9 性能与 Wazuh 日志联合分析

新增接口位于 `scripts/monitoring/performance.py`，使用 Python 标准库访问 VM9 本机 Prometheus 的 `/api/v1/query_range`。采集器每次按 30 秒步长读取历史窗口，使用游标续采，单次最多回看两小时。CPU、磁盘吞吐和网络吞吐使用两分钟 rate 窗口。

| 指标 | 单位 | 统计含义 |
|---|---|---|
| cpu_percent | % | 非空闲 CPU 时间占比 |
| memory_percent | % | 根据可用内存计算的使用比例 |
| load1 | load | 一分钟负载 |
| disk_used_percent | % | 排除临时文件系统后最高分区使用率 |
| disk_read_bytes_per_second | B/s | 主机磁盘读取速率 |
| disk_write_bytes_per_second | B/s | 主机磁盘写入速率 |
| network_rx_bytes_per_second | B/s | 非 loopback 接口接收速率总和 |
| network_tx_bytes_per_second | B/s | 非 loopback 接口发送速率总和 |
| target_up | 0 或 1 | Prometheus 抓取目标状态 |

`sensor_host` 固定为 VM9，`target_host` 表示指标实际所属主机。实例地址必须存在于配置的目标映射中。响应中的未知主机、非有限数值和越界时间点会被剔除。空结果和网络错误分别记录为 no_samples 和 unavailable，不生成零值样本。

## 入库与查询

每个样本包含时间、主机、实例、指标名、单位和值，以固定来源 `prometheus_performance` 入库。样本内容摘要用于去重。它属于辅助证据，不伪装成 Wazuh 规则告警。

`performance_metrics` 按主机和指标汇总窗口内全部已保存样本，返回样本数、最小值、最大值、平均值、峰值时间和末值。即使峰值出现在第 80 条之后，也参与统计。

`performance_correlations` 对本轮已选中的 Wazuh 事件进行同机时间匹配，默认查找事件前后 120 秒的指标。它保留告警原始事件编号与指标摘要，关系类型为 `same_host_temporal_overlap`。结果过多时明确标记截断，可通过 match 缩小到具体主机或指标。

业务接口探测同时保存成功、失败、HTTP 状态和耗时，从而保留故障后的恢复观测。HTTP 状态缺失时保持空值。

## 本地验收

测试使用构造的 Prometheus 响应和本地 SQLite，覆盖数据解析、错误与空响应、主机匹配、跨轮隔离、去重、峰值保留、告警关联及 Agent 工具权限。`make demo` 提供独立离线样例。VM9 本次离线，在线采集联调待其恢复后执行。

参考接口：https://prometheus.io/docs/prometheus/latest/querying/api/
