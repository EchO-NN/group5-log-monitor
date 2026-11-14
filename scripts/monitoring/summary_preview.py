"""Local, private preview of output-text deltas; never stores reasoning or API headers."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import time
import unicodedata


def stamp():return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic(path,value):
    temp=path.with_suffix('.tmp')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:json.dump(value,stream,ensure_ascii=False)
    temp.chmod(0o600);temp.replace(path)


class Preview:
    def __init__(self,root,job):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.root.chmod(0o700)
        attempt=hashlib.sha256((job['id']+job['token']).encode()).hexdigest()
        self.directory=self.root/attempt;self.directory.mkdir(mode=0o700,exist_ok=True)
        self.state=dict(job_id=job['id'],run=job['run'],case_id=job['case_id'],started_at=stamp(),
                        state='connecting',characters=0,request=0,last_event_at=None,last_text_at=None,error=None)
        self.last_save=0
        self.save()
        atomic(self.root/'latest.json',{'attempt':attempt})

    def save(self):
        self.state['updated_at']=stamp();atomic(self.directory/'status.json',self.state)
        self.last_save=time.monotonic()

    def stage(self,state,**values):
        self.state.update(values,state=state);self.save()

    def begin_request(self):
        number=self.state['request']+1
        path=self.directory/('output-'+str(number)+'.txt')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        self.stage('connecting',request=number,output=path.name,characters=0,last_event_at=None,last_text_at=None)

    def use_cached(self,answer):
        text=json.dumps(answer['result'],ensure_ascii=False,indent=2)
        path=self.directory/'cached-output.json'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:stream.write(text)
        self.stage('publishing',from_cache=True,output=path.name,characters=len(text))

    def event(self,kind,delta=None):
        at=stamp();self.state['last_event_at']=at
        if kind=='response.output_text.delta' and delta is not None:
            with (self.directory/self.state['output']).open('a') as stream:stream.write(delta)
            first=not self.state['characters']
            self.state.update(state='receiving',last_text_at=at,characters=self.state['characters']+len(delta))
            if first:self.save()
        elif self.state['state']=='connecting':self.state['state']='waiting_for_text'
        if time.monotonic()-self.last_save>=1:self.save()


def show(root,full=False):
    root=Path(root)
    if not (root/'latest.json').exists():
        print('尚无实时输出记录。此功能启用后的新请求会自动保存正文。');return
    attempt=json.loads((root/'latest.json').read_text())['attempt']
    if len(attempt)!=64 or any(c not in '0123456789abcdef' for c in attempt):raise ValueError('invalid preview')
    directory=root/attempt;state=json.loads((directory/'status.json').read_text())
    labels={'connecting':'正在连接模型','waiting_for_text':'连接已建立，尚未收到正文','receiving':'正在接收正文',
            'validating':'正文接收完毕，正在校验','publishing':'正在回写 IRIS','done':'已完成',
            'pending':'等待自动重试','failed':'处理失败','superseded':'新证据已替代该任务','conflict':'人工修改冲突',
            'lease_will_expire':'等待任务重新领取','investigating':'正在执行调查工具','choosing_tool':'正在接收下一步工具调用'}
    if state.get('agent'):
        labels.update(waiting_for_text='模型正在选择下一步调查工具',receiving='正在接收工具调用参数')
    local=lambda value:dt.datetime.fromisoformat(value).astimezone(dt.timezone(dt.timedelta(hours=8))).strftime('%m-%d %H:%M:%S') if value else '暂无'
    print('最近一次 AI 请求：Case #'+str(state['case_id'])+' / '+state['run'])
    print('状态：'+labels.get(state['state'],state['state'])+'；请求序号：'+str(state['request']))
    if state.get('agent'):
        print('调查步骤：'+str(state.get('agent_step',0))+'；当前操作：'+str(state.get('current_action','选择调查工具')))
        if state.get('purpose'):print('操作目的：'+state['purpose'])
        if state.get('current_action')=='inspect_files':print('只读文件：'+str(state.get('query_host',''))+' / '+str(state.get('file_path','')))
        if state.get('current_action')=='query_host' and state.get('audit_page'):print('审计分页：'+str(state.get('query_host',''))+' / 第 '+str(state['audit_page'])+' 页（每页最多 80 条，可续读）')
        for page in state.get('pending_audit_pages',[]):
            print('审计覆盖未完成：'+page['host']+' / '+page['reference']+('；还有下一页' if page.get('has_more') else '；存在读取缺口'))
        task_labels={'open':'待调查','investigating':'调查中','completed':'只读调查已完成','blocked':'受阻待处理'}
        for task in state.get('agent_tasks',[]):
            print('  '+task['id']+' / '+task_labels.get(task['state'],task['state'])+' / '+task['title'])
        for action in state.get('agent_actions',[])[-3:]:
            print('最近操作 '+str(action['step'])+'：'+action['tool']+' — '+action['purpose'])
    if state.get('from_cache'):print('使用已保存的完整正文，本次未调用模型。')
    print('开始：'+local(state['started_at'])+'；最近接口消息：'+local(state['last_event_at'])+'（北京时间）')
    print('已接收正文：'+str(state['characters'])+' 字符；最近正文：'+local(state['last_text_at']))
    if state.get('error'):
        errors={'provider_first_text_timeout':'等待首段正文超时','provider_output_idle_timeout':'正文停止增长超过空闲时限',
                'provider_total_timeout':'达到请求总时限','provider_deadline':'旧版固定 180 秒超时'}
        print('错误：'+errors.get(state['error'],state['error']))
    if state.get('timeouts'):
        limits=state['timeouts']
        print('超时设置：首段正文 '+str(int(limits['first_text_timeout_seconds']))+' 秒；正文无增长 '+str(int(limits['output_idle_timeout_seconds']))+' 秒；总时限 '+str(int(limits['request_total_timeout_seconds']))+' 秒')
    name=state.get('output');text=''
    if name and Path(name).name==name:
        text=(directory/name).read_text(errors='replace')
        print('正文文件：'+str(directory/name))
    print('以下为当前工具调用参数预览，实际执行结果见上方任务与操作记录。' if state.get('agent') else '以下为未校验的正文预览，可能尚未完整；不是推理过程。')
    if not full and len(text)>4000:print('……仅显示末尾 4000 字符；ai --full 可看完整已接收正文。')
    text=text if full else text[-4000:]
    print(''.join(c for c in text if c in '\n\t' or not unicodedata.category(c).startswith('C')) or '（尚未收到正文）')
