"""Noninteractive end-to-end demo; temporary credentials and state never persist."""
import json,secrets,tempfile
from pathlib import Path
from .core import Lab
from .research import score_live

def main():
    with tempfile.TemporaryDirectory() as tmp:
        lab=Lab.initialize(Path(tmp)/'sandbox');password=secrets.token_urlsafe(24)
        lab.provision('demo-tech',password,'technician','food-a')
        token=lab.login('demo-tech',password)
        print('Allowed sample:',lab.act(token,'read','S001')['id'])
        lab.act(token,'write','S001','Simulated pH: 6.6')
        for action,sample in [('read','S002'),('export','S001')]:
            try: lab.act(token,action,sample)
            except PermissionError: print('Expected denial:',action,sample)
            else: raise AssertionError('Unauthorized action succeeded')
        lab.act(token,'logout');print('Audit chain valid:',bool(lab.verify()))
        print('Illustrative offline scores:',json.dumps(score_live(lab.events(),'data/windows.csv'),indent=2))
        lab.db.close()
if __name__=='__main__': main()
