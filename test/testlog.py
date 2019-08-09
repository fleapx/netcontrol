# -*- coding: utf-8 -*-

"""
Usage:
    python testlog.py /var/log/taurus.log
"""

import json
import sys

if __name__ == '__main__':
    f = open(sys.argv[1])
    dstip_list = set(list())
    exe_list = dict()
    dstip = ''
    for line in f.readlines():
        if line.find('RMJU') == -1:
            continue
        try:
            line = line.replace('RMJU:', '')
            curjson = json.loads(line)
            if 'exe' in curjson:
                exe = curjson['exe']
                if exe not in exe_list:
                    exe_list[exe] = 0
                exe_list[exe] += 1
            if 'cmd' in curjson:
                dstip = curjson['dstip']
            if 'judge' in curjson:
                if int(curjson['judge']) < 0:
                    dstip_list.add(dstip)
        except Exception as e:
            continue
    print(dstip_list)
    print(exe_list)