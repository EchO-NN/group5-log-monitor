"""Explicit prior-plan mapping for classroom demonstrations, not attack verdicts."""
import html
import json
from pathlib import Path
import re

from triage import SUPPORT

NOTICE='课堂预设流程映射：依据事先配置的演练方案整理证据，不代表实时攻击进度或攻击成功。'


def definitions():
    return json.loads(Path(__file__).with_name('stages.json').read_text())


def mapped_stages(kinds):
    # Routine measurements alone must not suggest a specific attack step.
    signals=set(kinds)-SUPPORT
    return [s['id'] for s in definitions() if signals.intersection(s['required'])]


def decorate_alert(rows,title,description):
    kinds={k for row in rows for k in json.loads(row['kinds'])}
    stages=mapped_stages(kinds)
    prefix='课堂预设阶段 '+ '/'.join(map(str,stages)) if stages else '课堂：未映射阶段'
    return (prefix+' | '+title)[:240],description+'\n'+NOTICE,dict(stage_ids=stages,meaning=NOTICE)


def snapshot(store,run):
    coverage=store.coverage(run);stages=[]
    for stage in coverage['stages']:
        observations=stage['observations']
        relevant={eid for kind,ids in observations.items() if kind not in SUPPORT for eid in ids}
        supporting={eid for kind,ids in observations.items() if kind in SUPPORT for eid in ids}
        if relevant:
            state='预设证据类型已齐' if not stage['missing'] else '已见相关行为，证据未齐'
        else:state='仅有辅助记录' if supporting else '待采集'
        stages.append(dict(id=stage['id'],name=stage['name'],state=state,
            related_event_count=len(relevant),supporting_event_count=len(supporting),
            observations=observations,missing=stage['missing'],analyst_confirmation=stage['analyst_confirmation']))
    return dict(notice=NOTICE,stages=stages,operator_markers=coverage['stage_markers'])


def render(data):
    headings=['预设阶段','名称','证据状态','相关行为记录','辅助记录','人工核实']
    rows=[[s['id'],s['name'],s['state'],s['related_event_count'],s['supporting_event_count'],
           '已有人工记录' if s['analyst_confirmation'] else '待核实'] for s in data['stages']]
    markdown='\n'.join(['## 课堂预设阶段证据概览',NOTICE,
        '同一记录可关联多个阶段；相关行为数量不是成功次数，辅助记录不表示攻击开始。','',
        '|'+'|'.join(headings)+'|','|'+'|'.join(['---']*len(headings))+'|',
        *['|'+'|'.join(str(x).replace('|','\\|') for x in row)+'|' for row in rows]])
    markup='<section><h2>课堂预设阶段证据概览</h2><p>'+html.escape(NOTICE)+'</p><p>同一记录可关联多个阶段；相关行为数量不是成功次数，辅助记录不表示攻击开始。</p><table><thead><tr>'+''.join('<th>'+html.escape(x)+'</th>' for x in headings)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+html.escape(str(x))+'</td>' for x in row)+'</tr>' for row in rows)+'</tbody></table></section>'
    return markdown,markup


def sync_tasks(client,run,data):
    current=client.request('case/tasks/list?cid='+str(client.cid))['tasks'];result={}
    for stage in data['stages']:
        marker='G5DEMO '+run+' S'+str(stage['id']).zfill(2)
        title=marker+' 课堂预设：'+stage['name']
        block='<!-- G5DEMO_BEGIN -->\n'+json.dumps(dict(stage,meaning=NOTICE),ensure_ascii=False,indent=2)+'\n<!-- G5DEMO_END -->'
        task=next((t for t in current if t['task_title'].startswith(marker+' ')),None)
        if task:
            old=task.get('task_description') or ''
            description=re.sub(r'<!-- G5DEMO_BEGIN -->.*?<!-- G5DEMO_END -->',lambda _:block,old,flags=re.S) if '<!-- G5DEMO_BEGIN -->' in old else old+'\n'+block
            if description!=old:
                client.request('case/tasks/update/'+str(task['task_id'])+'?cid='+str(client.cid),dict(
                    task_title=task['task_title'],task_description=description,task_status_id=task['task_status_id'],
                    task_tags=task.get('task_tags',''),task_assignees_id=[a['id'] for a in task.get('task_assignees',[])],
                    custom_attributes=task.get('custom_attributes') or {}))
            result[str(stage['id'])]=task['task_id']
        else:
            created=client.request('case/tasks/add?cid='+str(client.cid),dict(task_title=title,task_description=block,
                task_status_id=1,task_assignees_id=[],task_tags='G5DEMO,PRESET_MAPPING',custom_attributes={}))
            result[str(stage['id'])]=created.get('task_id',created.get('id'))
    return result
