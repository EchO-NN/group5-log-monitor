"""VM9 Prometheus collection and time-based evidence correlation (stdlib only)."""
import datetime as dt
import hashlib
import json
import math
import re
import urllib.parse
import urllib.request
from collections import defaultdict

UTC = dt.timezone.utc
SOURCE = 'prometheus_performance'
TARGETS = {
    '192.168.59.10:9100': 'VM2', '192.168.33.15:9100': 'VM3',
    '192.168.32.20:9100': 'VM4', '192.168.31.30:9100': 'VM5',
    '192.168.30.40:9100': 'VM6', '192.168.29.50:9100': 'VM7',
    '192.168.50.10:9100': 'VM8', '192.168.50.11:9100': 'VM9',
}
# Each expression returns one series per instance. The collector drops unknown targets.
METRICS = {
    'cpu_percent': ('percent', '100*(1-avg by(instance)(rate(node_cpu_seconds_total{mode="idle"}[2m])))'),
    'memory_percent': ('percent', '100*(1-max by(instance)(node_memory_MemAvailable_bytes)/max by(instance)(node_memory_MemTotal_bytes))'),
    'load1': ('load', 'max by(instance)(node_load1)'),
    'disk_used_percent': ('percent', 'max by(instance)(100*(1-node_filesystem_avail_bytes{fstype!~"tmpfs|devtmpfs|overlay|squashfs"}/node_filesystem_size_bytes{fstype!~"tmpfs|devtmpfs|overlay|squashfs"}))'),
    'disk_read_bytes_per_second': ('bytes/second', 'sum by(instance)(rate(node_disk_read_bytes_total{device!~"loop.*|ram.*"}[2m]))'),
    'disk_write_bytes_per_second': ('bytes/second', 'sum by(instance)(rate(node_disk_written_bytes_total{device!~"loop.*|ram.*"}[2m]))'),
    'network_rx_bytes_per_second': ('bytes/second', 'sum by(instance)(rate(node_network_receive_bytes_total{device!="lo"}[2m]))'),
    'network_tx_bytes_per_second': ('bytes/second', 'sum by(instance)(rate(node_network_transmit_bytes_total{device!="lo"}[2m]))'),
    'target_up': ('boolean', 'min by(instance)(up)'),
}


def iso(value):
    return dt.datetime.fromtimestamp(float(value), UTC).isoformat()


def epoch(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def normalized_point(metric, instance, when, value, targets=None):
    targets = TARGETS if targets is None else targets
    if metric not in METRICS or instance not in targets:
        return None
    try:
        if isinstance(value, bool) or isinstance(when, bool):
            return None
        value, when = float(value), float(when)
        if not math.isfinite(value) or not math.isfinite(when) or value < 0:
            return None
        at = iso(when)
    except (ValueError, TypeError, OverflowError, OSError):
        return None
    unit = METRICS[metric][0]
    if unit == 'percent' and value > 100.001:
        return None
    if metric == 'target_up' and value not in (0, 1):
        return None
    return dict(at=at, sensor_host='VM9', target_host=targets[instance],
                instance=instance, metric=metric, value=round(value, 6), unit=unit)


def collect(start, end, *, base_url='http://127.0.0.1:9090', step=30,
            targets=None, opener=None):
    """Read a bounded historical window; never replace missing samples with zero."""
    if not 0 <= end - start <= 7200 or step < 15:
        raise ValueError('invalid performance window')
    url = urllib.parse.urlsplit(base_url)
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('invalid Prometheus URL')
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    points, states = {}, {}
    for name, (_, expression) in METRICS.items():
        params = urllib.parse.urlencode(dict(query=expression, start=start, end=end, step=step, timeout='4s'))
        try:
            with opener.open(base_url.rstrip('/') + '/api/v1/query_range?' + params, timeout=5) as response:
                body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                raise ValueError('response too large')
            payload = json.loads(body)
            if payload.get('status') != 'success' or payload.get('data', {}).get('resultType') != 'matrix':
                raise ValueError('invalid Prometheus result')
            count = 0
            for series in payload['data'].get('result', []):
                instance = series.get('metric', {}).get('instance')
                for sample in series.get('values', []):
                    if not isinstance(sample, list) or len(sample) != 2:
                        continue
                    point = normalized_point(name, instance, sample[0], sample[1], targets)
                    if point and start <= epoch(point['at']) <= end:
                        points[(name, instance, point['at'])] = point
                        count += 1
            states[name] = 'available' if count else 'no_samples'
            if payload.get('warnings'):
                states[name] = 'partial_response'
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            states[name] = 'unavailable'
    return dict(points=sorted(points.values(), key=lambda p: (p['at'], p['instance'], p['metric'])),
                metrics=states, complete=all(s in ('available', 'no_samples') for s in states.values()),
                start=iso(start), end=iso(end), step_seconds=step)


def event(point):
    digest = hashlib.sha256(json.dumps(point, sort_keys=True).encode()).hexdigest()
    return dict(id='vm9-performance:' + digest, timestamp=point['at'],
                agent={'name': 'group5-vm9', 'id': 'management-vm9'},
                location=SOURCE, full_log='VM9 Prometheus 性能采样',
                data=dict(point, group5={'kind': 'performance_metric'}),
                provenance={'channel': 'prometheus_query_range', 'sensor': 'VM9'})


def parse(event_data, at):
    data = event_data.get('data') or {}
    if (data.get('group5') or {}).get('kind') != 'performance_metric':
        return None
    try:
        point = normalized_point(data.get('metric'), data.get('instance'), epoch(at), data.get('value'))
    except (ValueError, TypeError, AttributeError):
        return None
    return point


def summarize(points):
    groups = defaultdict(list)
    for point in points:
        groups[(point['target_host'], point['metric'], point['instance'])].append(point)
    rows = []
    for (host, metric, instance), group in sorted(groups.items()):
        group.sort(key=lambda p: p['at'])
        values = [p['value'] for p in group]
        peak = max(group, key=lambda p: p['value'])
        rows.append(dict(at=group[0]['at'], first_seen=group[0]['at'], last_seen=group[-1]['at'],
                         target_host=host, sensor_host='VM9', metric=metric, instance=instance,
                         unit=METRICS[metric][0], samples=len(group), minimum=min(values), maximum=max(values),
                         average=round(sum(values)/len(values), 6), peak_at=peak['at'],
                         last_value=group[-1]['value'], source=SOURCE,
                         source_event_ids=sorted({i for p in group for i in p.get('source_event_ids', [])})[:8],
                         source_digest=hashlib.sha256(json.dumps(group, sort_keys=True).encode()).hexdigest()))
    return rows


def host_identity(agent):
    ip = agent.get('ip', '')
    if ip + ':9100' in TARGETS:
        return TARGETS[ip + ':9100']
    name = agent.get('name', '').lower()
    aliases = {'admin': 'VM3', 'vm2-gateway': 'VM2', 'vm4-fire-file': 'VM4',
               'vm7-backup-srv': 'VM7', 'vm8-log-mon': 'VM8'}
    if name in aliases:
        return aliases[name]
    match = re.fullmatch(r'(?:group5-)?vm([2-9])', name)
    return 'VM' + match[1] if match else None


def correlate(points, alerts, window_seconds=120):
    """Only associate samples for the same protected host near each alert."""
    rows = []
    for alert in alerts:
        host = host_identity(alert.get('agent') or {})
        try:
            at = epoch(alert['timestamp'])
        except (KeyError, TypeError, ValueError):
            continue
        nearby = [p for p in points if p['target_host'] == host and abs(epoch(p['at'])-at) <= window_seconds]
        if not nearby:
            continue
        rows.append(dict(at=alert['timestamp'], target_host=host, source=SOURCE,
                         alert_event_id=alert['source_event_id'], rule_id=str(alert.get('rule', {}).get('id', '')),
                         relation='same_host_temporal_overlap', window_seconds=window_seconds,
                         interpretation='同机同时段的观测关联，因果关系需结合操作日志与业务结果判断。',
                         metrics=summarize(nearby)))
    return rows
