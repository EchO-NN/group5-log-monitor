"""Describe observed risk events without inferring an attack workflow."""
import datetime as dt
import hashlib
import json
import re

# Routine observations remain evidence; they do not imply attack progress.
SUPPORT = {'performance_metric', 'business_probe_success', 'acl_allow','sql_read','command_execution','vm3_cpu','backup_inventory',
           'application_log_snapshot','central_original_preserved','cross_host_timeline',
           'stage_marker','analyst_confirmation','mail_sample','browser_record',
           'restore_verification','offline_backup_verification','log_hash_comparison'}
LABELS = {
 'web_request':'Web 请求记录', 'ssh_login':'SSH 远程登录',
 'discovery_process':'网络扫描工具执行', 'acl_drop':'跨网段访问被拒绝',
 'sensitive_file_access':'员工机敏感文件访问', 'credential_tool':'凭据恢复工具执行',
 'smb_access':'SMB 共享访问', 'git_execution':'Git 命令执行',
 'ssh_publickey':'应用服公钥认证', 'ssh_password':'应用服口令认证',
 'sudoedit_activity':'sudoedit 权限操作', 'privilege_identity':'身份切换至高权限',
 'sensitive_config_access':'应用敏感配置访问', 'sql_export':'数据库导出',
 'data_transfer':'数据传输记录', 'backup_login':'备份账号远程登录',
 'backup_change':'备份文件变化', 'backup_integrity_failure':'备份完整性校验失败',
 'sql_change':'数据库变更语句', 'application_sql_error':'应用数据库错误',
 'business_probe_failure':'业务接口探测失败', 'application_log_change':'应用日志完整性变化',
 'acl_allow':'网络放行', 'sql_read':'数据库读取', 'command_execution':'命令执行记录',
 'vm3_cpu':'CPU 采样', 'pipeline_selftest':'监控链路自测', 'wazuh_detection':'Wazuh 规则告警'}


def audit_arguments(event):
    """Decode audit hex arguments for detection only; never publish decoded secrets."""
    raw=str(event.get('full_log',''))[:65536]
    if 'EXECVE' not in raw and 'PROCTITLE' not in raw: return ''
    parts=[]
    for quoted,hexed in re.findall(r'\b(?:a\d+|proctitle)=(?:"([^"]*)"|([0-9a-fA-F]+))',raw)[:64]:
        try: value=quoted or bytes.fromhex(hexed[:8192]).decode('utf-8').replace('\x00',' ')
        except (ValueError,UnicodeError): continue
        parts.append(value[:4096])
    return ' '.join(parts)[:16384]


def needs_alert(envelope,kinds):
    event=envelope.get('event',{});rule=event.get('rule',{})
    try: level=int(rule.get('level',0))
    except (ValueError,TypeError): level=0
    if level>=7: return True  # A matching Wazuh detection must not be suppressed by a routine label.
    # Observed behaviors remain reviewable when only raw audit is available.
    return bool(set(kinds)-SUPPORT)


def group_key(row):
    envelope=json.loads(row['payload']);event=envelope.get('event',{});kinds=json.loads(row['kinds'])
    bucket=int(dt.datetime.fromisoformat(row['event_time']).timestamp())//300
    agent=event.get('agent',{});data=event.get('data',{})
    key=[row['run'],agent.get('id'),agent.get('name'),sorted(kinds),event.get('rule',{}).get('id'),
         data.get('srcip'),data.get('dstip'),bool(row['selftest']),bucket]
    return hashlib.sha256(json.dumps(key,sort_keys=True).encode()).hexdigest()


def alert_text(rows):
    rows=sorted(rows,key=lambda r:(dt.datetime.fromisoformat(r['event_time']),r['id']))
    first=rows[0];envelope=json.loads(first['payload']);event=envelope.get('event',{})
    kinds=sorted({k for row in rows for k in json.loads(row['kinds'])});labels=[LABELS.get(k,k) for k in kinds if k not in SUPPORT] or [LABELS.get(k,k) for k in kinds]
    host=event.get('agent',{}).get('name','未知主机');rule=event.get('rule',{})
    title=('TEST ' if first['selftest'] else '')+str(host)+' | '+'、'.join(labels)
    description='\n'.join(['观察行为：'+'、'.join(labels),'主机：'+str(host),
        '事件时间（UTC）：'+first['event_time']+' 至 '+rows[-1]['event_time'],
        '同一主机和行为，5 分钟窗口内合并：'+str(len(rows))+' 条',
        '检测依据：'+(str(rule.get('id'))+' / '+str(rule.get('description','')) if rule.get('id') else '原始日志行为特征：'+', '.join(kinds)),
        '原始来源：'+str(event.get('location',first['source'])),
        '判断状态：行为已观察；是否为授权操作及其影响待核实。'])
    return title[:240],description
