# 构建与验证

## Wazuh 源码编译

本次取 Wazuh v4.14.9 标签源码，执行 `make TARGET=agent deps` 和 `make TARGET=agent -j2`。构建生成 wazuh-agentd、wazuh-logcollector、wazuh-syscheckd、wazuh-execd 和 wazuh-modulesd。版本检查在独立临时目录运行，没有替换实验环境的服务。

[构建记录](verification/wazuh-source-build.json)包含源码地址、源包 SHA-256、编译器、五个程序的摘要和版本输出。复现入口为 `scripts/build-wazuh-agent.sh`。编译所需工具参见 [Wazuh 官方安装说明](https://documentation.wazuh.com/current/deployment-options/wazuh-from-sources/wazuh-agent/index.html)。上游源码与编译产物没有打包进本仓库。

## 项目测试与打包

```bash
make test
make compile
python -m build
make demo
python3 scripts/check-publication.py
```

单元测试覆盖告警筛选、独立 Case、重试与流式状态、审计分页、文件读取、IRIS 增量写入和 VM9 性能关联。离线样例检查采样入库后，能否返回同一主机附近的 Wazuh 事件。测试统计见 [local-tests.json](verification/local-tests.json)。

本地测试通过说明代码接口和相应边界按预期运行；VM9 的在线联调单独记录，当前状态为待上线。

## 实际场景与远程核查

11 月 5 日 Case 2 使用真实实验日志完成跨机器核查。认证日志、VM5 和 VM7 审计、数据库操作、应用错误及业务探测构成实际场景材料。远程只读查询的结果保留引用和来源摘要，原始运行文件保存在实验环境，公开仓库提供脱敏结论。

## 发布检查

公开目录从监控源码白名单建立。密钥文件、原始日志、运行数据库、浏览器数据和旧备份不复制。发布前同时检查常见凭据格式和本地已知密钥的精确匹配，检查结果只输出计数与文件名，不输出密钥内容。
