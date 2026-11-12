#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2024/4/23:10:34
# email:peiwenping@finslink.com
#解析 config配置文件

import configparser
import os

BASE_DIR = os.getcwd() + '/Resource/Lib/parseLib/config'
#BASE_DIR = os.getcwd() + '/config'   #py调试时打开，rf使用时注释

split = lambda x,sep: str(x).split(sep) if x else x

class netflow:
    def __init__(self,configName):
        self.configName = configName
        self.config = configparser.ConfigParser()
        self.config.read(os.path.join(BASE_DIR, "%s.ini"%configName))

    def getNetflow(self,title='rule'):
        return dict(self.config[title])



if __name__ == "__main__":
    a = netflow("netflow")
    c = a.getNetflow("netflow_v4")
    print(c)