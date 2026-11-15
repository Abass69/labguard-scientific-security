"""Synthetic benchmark. Labels and scenario names never enter model features."""
import csv, hashlib, json, platform
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score
FEATURES=['requests','denials','failed_logins','exports','records','off_hours']

def aggregate(events):
    groups=defaultdict(list)
    for e in events: groups[(e['actor'],int(e['ts']//900))].append(e)
    rows=[]
    for (actor,bucket),batch in sorted(groups.items(),key=lambda item:item[0][1]):
        hour=datetime.fromtimestamp(bucket*900,timezone.utc).hour
        rows.append(dict(actor=actor,bucket=bucket,requests=len(batch),
            denials=sum(e['outcome']=='deny' for e in batch),
            failed_logins=sum(e['action']=='login' and e['outcome']=='deny' for e in batch),
            exports=sum(e['action']=='export' and e['outcome']=='allow' for e in batch),
            records=sum(e['records'] for e in batch),off_hours=int(hour<7 or hour>=19)))
    return rows

def generate(seed=42):
    rng=np.random.default_rng(seed);events=[];labels={}
    for day in range(60):
        split='train' if day<30 else 'calibration' if day<40 else 'test'
        for user in range(12):
            scenario='normal'
            if split=='test' and rng.random()<.18:
                scenario=str(rng.choice(['login_burst','scope_probe','bulk_export','quiet_misuse']))
            elif rng.random()<.12: scenario='legitimate_batch'
            hour=int(rng.integers(8,18)) if rng.random()<.93 else int(rng.choice([1,3,21]))
            ts=1767225600+day*86400+hour*3600;actor=f'user-{user:02d}'
            count=int(rng.poisson(15)+3)
            if scenario=='legitimate_batch': count+=int(rng.integers(30,90))
            if scenario in {'scope_probe','login_burst'}: count+=int(rng.integers(15,65))
            if scenario=='bulk_export': count+=int(rng.integers(15,50))
            for i in range(count):
                action=str(rng.choice(['read','write','export','login'],p=[.70,.20,.04,.06]))
                outcome='deny' if rng.random()<.025 else 'allow'
                records=int(rng.integers(1,7)) if action=='export' else int(action in {'read','write'})
                if scenario=='login_burst' and rng.random()<.60: action,outcome,records='login','deny',0
                if scenario=='scope_probe' and rng.random()<.50: action,outcome,records='read','deny',0
                if scenario=='bulk_export' and rng.random()<.35: action,outcome,records='export','allow',int(rng.integers(3,12))
                if scenario=='legitimate_batch' and rng.random()<.14: action,outcome,records='export','allow',int(rng.integers(3,12))
                if outcome=='deny': records=0
                events.append(dict(ts=ts+i,actor=actor,action=action,outcome=outcome,project='food-a' if user%2 else 'food-b',records=records))
            labels[(actor,ts//900)]=dict(day=day,split=split,scenario=scenario,label=int(scenario not in {'normal','legitimate_batch'}))
    rows=aggregate(events)
    for row in rows: row.update(labels[(row['actor'],row['bucket'])])
    return events,rows

def matrix(rows): return np.asarray([[float(r[f]) for f in FEATURES] for r in rows])

def fit(rows):
    model=IsolationForest(n_estimators=200,max_samples=256,random_state=42,n_jobs=1)
    model.fit(matrix([r for r in rows if r['split']=='train']))
    scores=-model.score_samples(matrix([r for r in rows if r['split']=='calibration']))
    return model,float(np.quantile(scores,.95,method='higher'))

def rule(rows):
    return np.array([int(float(r['failed_logins'])>=5 or float(r['denials'])>=10 or (float(r['exports'])>=8 and float(r['records'])>=60)) for r in rows])

def metrics(y,pred,scores=None):
    tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    result=dict(precision=float(precision_score(y,pred,zero_division=0)),recall=float(recall_score(y,pred,zero_division=0)),f1=float(f1_score(y,pred,zero_division=0)),false_positive_rate=float(fp/(tn+fp)),tn=int(tn),fp=int(fp),fn=int(fn),tp=int(tp))
    if scores is not None: result.update(average_precision=float(average_precision_score(y,scores)),roc_auc=float(roc_auc_score(y,scores)))
    return result

def score_live(events,reference):
    with open(reference) as f: rows=list(csv.DictReader(f))
    model,threshold=fit(rows);live=aggregate(events)
    if not live: return []
    scores=-model.score_samples(matrix(live))
    return [{**r,'score':float(s),'threshold':threshold,'alert':bool(s>threshold),'rule_alert':bool(p)} for r,s,p in zip(live,scores,rule(live))]

def run(seed=42,output='.'):
    root=Path(output)
    for folder in ['data','results']: (root/folder).mkdir(parents=True,exist_ok=True)
    events,rows=generate(seed);raw=root/'data/events.jsonl'
    raw.write_text(''.join(json.dumps(e,sort_keys=True)+'\n' for e in events))
    with (root/'data/windows.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    model,threshold=fit(rows);test=[r for r in rows if r['split']=='test']
    scores=-model.score_samples(matrix(test));y=np.array([r['label'] for r in test]);pred=scores>threshold;baseline=rule(test)
    result=dict(seed=seed,events=len(events),windows=len(rows),features=FEATURES,
        split_counts={s:sum(r['split']==s for r in rows) for s in ['train','calibration','test']},
        test_anomalies=int(y.sum()),threshold=threshold,isolation_forest=metrics(y,pred,scores),rules=metrics(y,baseline),
        by_scenario={},raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),
        environment=dict(python=platform.python_version(),numpy=np.__version__,sklearn=sklearn.__version__))
    for scenario in sorted({r['scenario'] for r in test}):
        ix=np.array([r['scenario']==scenario for r in test])
        result['by_scenario'][scenario]=dict(windows=int(ix.sum()),iforest_alert_rate=float(pred[ix].mean()),rules_alert_rate=float(baseline[ix].mean()))
    rng=np.random.default_rng(seed+1000);boot=[]
    for _ in range(500):
        ix=rng.integers(0,len(y),len(y));boot.append(f1_score(y[ix],pred[ix],zero_division=0))
    result['iforest_f1_bootstrap_95_percentile']=np.quantile(boot,[.025,.975]).tolist()
    (root/'results/metrics.json').write_text(json.dumps(result,indent=2)+'\n')
    with (root/'results/predictions.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(test[0])+['score','iforest_alert','rule_alert']);w.writeheader()
        for r,s,p,b in zip(test,scores,pred,baseline): w.writerow({**r,'score':s,'iforest_alert':int(p),'rule_alert':int(b)})
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,2,figsize=(10,4),layout='constrained')
    for label,color in [(0,'#247C91'),(1,'#C25D32')]:
        axes[0].hist(scores[y==label],bins=18,alpha=.7,label='Benign' if label==0 else 'Injected anomaly',color=color)
    axes[0].axvline(threshold,color='black',linestyle='--',label='Calibration threshold')
    axes[0].set(xlabel='Isolation Forest anomaly score',ylabel='Test windows',title='Held-out synthetic test');axes[0].legend(fontsize=8)
    names=['Precision','Recall','F1','False-positive rate'];keys=['precision','recall','f1','false_positive_rate'];x=np.arange(4)
    for offset,key,label,color in [(-.18,'rules','Rules','#247C91'),(.18,'isolation_forest','Isolation Forest','#C25D32')]:
        axes[1].bar(x+offset,[result[key][k] for k in keys],width=.36,label=label,color=color)
    axes[1].set(xticks=x,xticklabels=names,ylim=(0,1),title='Rules versus learned detector');axes[1].tick_params(axis='x',labelsize=8);axes[1].legend()
    fig.savefig(root/'results/performance.png',dpi=180);plt.close(fig)
    return result
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--seed',type=int,default=42);p.add_argument('--output',default='.')
    a=p.parse_args();print(json.dumps(run(a.seed,a.output),indent=2))
