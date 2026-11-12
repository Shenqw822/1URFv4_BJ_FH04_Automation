#!/bin/bash/env python
#-*- coding:utf-8 -*-
#Author PeiWenPing
#time:2024/5/8:16:41
#email:peiwenping@finslink.com

#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2024/4/23:10:34
# email:peiwenping@finslink.com
#解析 config配置文件

import configparser
import os

# BASE_DIR = os.getcwd() + '/Resource/Lib/rcpLib/config'
BASE_DIR = os.getcwd() + '/config'
config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, 'config.ini'))

split = lambda x,sep: str(x).split(sep) if x else x

CLIENT = {
    'host_ip': config.get('client', 'dst_ip'),
    'dev_id': config.get('client', 'dev_id'),
    'ssl_switch': int(config.get('client', 'ssl_switch'))}

SERVER = {
    'server_ip': config.get('netcard', 'server_ip'),
    'username': config.get('netcard', 'username'),
    'password': config.get('netcard', 'password'),
    'nic': config.get('netcard', 'nic')
}
class R3:
    def __init__(self,configName):
        self.configName = configName
        self.config = configparser.ConfigParser()
        self.config.read(os.path.join(BASE_DIR, "%s.ini"%configName))

    def setR3(self,title,col,value):
        self.config.set(title,col,str(value))
        with open(os.path.join(BASE_DIR, "%s.ini"%self.configName),'w') as f:
            self.config.write(f)

    def getMirror(self):
        PARAMS = {'percent': self.config.get('mirror', 'percent'),
                  'outgroup_id': self.config.get('mirror', 'outgroup_id'), }
        return PARAMS


    def getAlarm(self):
        PARAMS = {'total_percent': self.config.get('alarm', 'total_percent'),
                  'day_percent': self.config.get('alarm', 'day_percent'),
                  'time_percent': self.config.get('alarm', 'time_percent'), }
        return PARAMS



if __name__ =='__main__':
    c = R3('forward0508')
    c.setR3('forwardRcp_2',"starttime",37890)