import argparse
import getpass
import json
from .core import Lab

def main():
    parser = argparse.ArgumentParser(description='Local-only LabGuard sandbox')
    parser.add_argument('--directory', default='.labguard')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init')
    p = sub.add_parser('provision'); p.add_argument('user'); p.add_argument('role'); p.add_argument('project')
    p = sub.add_parser('act'); p.add_argument('user'); p.add_argument('action'); p.add_argument('--sample', default='S001'); p.add_argument('--value')
    sub.add_parser('verify')
    p = sub.add_parser('score'); p.add_argument('--reference', default='data/windows.csv')
    args = parser.parse_args()
    if args.command == 'init':
        lab = Lab.initialize(args.directory)
        print('Initialized fictional samples. Provision local users next.')
    else:
        lab = Lab(args.directory)
        if args.command == 'provision':
            lab.provision(args.user, getpass.getpass('New password (14+ characters): '), args.role, args.project)
        elif args.command == 'verify':
            print(lab.verify())
        elif args.command == 'score':
            from .research import score_live
            print(json.dumps(score_live(lab.events(), args.reference), indent=2))
        else:
            token = lab.login(args.user, getpass.getpass())
            try:
                print(json.dumps(lab.act(token, args.action, args.sample, args.value), indent=2))
            finally:
                if args.action != 'logout': lab.act(token, 'logout')
    lab.db.close()

if __name__ == '__main__':
    main()
