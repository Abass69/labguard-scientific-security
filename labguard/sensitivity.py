"""Fixed-design replication across simulator seeds; no threshold tuning on tests."""
import json
from pathlib import Path
import numpy as np
from .research import generate,fit,matrix,metrics,rule

def main():
    results=[]
    for seed in [42,43,44,45,46]:
        _,rows=generate(seed);model,threshold=fit(rows);test=[r for r in rows if r['split']=='test']
        scores=-model.score_samples(matrix(test));y=np.array([r['label'] for r in test])
        results.append(dict(seed=seed,threshold=threshold,isolation_forest=metrics(y,scores>threshold,scores),rules=metrics(y,rule(test))))
    Path('results/sensitivity.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))
if __name__=='__main__': main()
