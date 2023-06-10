#!/usr/bin/python3

import time
import argparse
import sys
import json


def main() -> int:
    parser = argparse.ArgumentParser(description='execute bmc command.')
    parser.add_argument('payload')
    parser.add_argument('headers')
    args = parser.parse_args()

    headers = json.loads(args.headers)
    #print('signature:', headers["X-Rufio-Signature-256"])
    #print('headers:', headers)
    payload = json.loads(args.payload)
    #print('host:', payload["host"])

    if payload['task'].get('power') != None:
        #print(payload['task'].get('power'))
        print('do power action')
    elif payload['task'].get('bootDevice') != None:
        print('do boot device action')
    else:
        print('unknown action')
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())