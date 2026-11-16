#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2024/4/23:10:34
# email:peiwenping@finslink.com
#解析 config配置文件

import configparser
import os

#BASE_DIR = os.getcwd() + '/Resource/Lib/rcpLib/config'   # 依赖 cwd，仅从 1URFv4_BJ_NEW 目录运行时正确，已弃用
##BASE_DIR = 'C:\\Users\\peiwe\\Desktop\\1URFv4_BJ\\Resource\\Lib\\rcpLib\\config'
##BASE_DIR = os.getcwd() + '/config'
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) + '/config'   # 用 __file__ 定位，不依赖 cwd，py 调试和 RF 运行均适用


config = configparser.ConfigParser()
with open(os.path.join(BASE_DIR, 'config.ini'), 'r', encoding='utf-8') as f:
    config.read_file(f)


split = lambda x,sep: str(x).split(sep) if x else x

CLIENT = {
    'host_ip': config.get('client', 'dst_ip'),
    'dev_id': config.get('client', 'dev_id'),
    'ssl_switch': int(config.get('client', 'ssl_switch'))}


def reloadClientConfig():
    """重新读取 config.ini 的 [client] 段并原地更新 CLIENT。

    RF 在导入库时就创建了 RCP 连接，而用例里的 changeConfigOptionValue
    只改了 config.ini 文件，CLIENT 仍是导入时的旧值。改完配置后调用本函数，
    可让本次运行立即使用新的 host_ip / dev_id / ssl_switch。
    """
    cfg = configparser.ConfigParser()
    with open(os.path.join(BASE_DIR, 'config.ini'), 'r', encoding='utf-8') as f:
        cfg.read_file(f)
    CLIENT['host_ip'] = cfg.get('client', 'dst_ip')
    CLIENT['dev_id'] = cfg.get('client', 'dev_id')
    CLIENT['ssl_switch'] = int(cfg.get('client', 'ssl_switch'))
    return CLIENT


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
        with open(os.path.join(BASE_DIR, "%s.ini"%configName), 'r', encoding='utf-8') as f:
            self.config.read_file(f)

    def getR3(self,title='rule'):
        PARAMS = {'operate': self.config.get(title, 'operate'),
                 'modify_type': self.config.get(title, 'modify_type'),
                 'expect_code': self.config.get(title, 'expect_code'),
                 'v4v6': self.config.get(title, 'v4v6'),
                 'sipg': [ split(i,',') for i in split(self.config.get(title, 'sipg'),';') if i],
                 'dipg': [ split(i,',') for i in split(self.config.get(title, 'dipg'),';') if i],
                 #'limit_type': self.config.get(title, 'limit_type') if self.config.get(title, 'limit_type') else 0,
                  'limit_type': self.config.get(title, 'limit_type') if self.config.has_option(title, 'limit_type') else 0,
                 'total': self.config.get(title, 'total') if self.config.get(title, 'total') and self.config.get(title, 'total') != '0' else 0 ,
                 'day': self.config.get(title, 'day') if self.config.get(title, 'day') and self.config.get(title, 'day')!='0' else 0,
                 'starttime': self.config.get(title, 'starttime') if self.config.get(title, 'starttime') and self.config.get(title, 'starttime') !='0' else 0,
                 'endtime': self.config.get(title, 'endtime') if self.config.get(title, 'endtime') else 0,
                 'expect_cost_total': self.config.get(title, 'expect_cost_total') if self.config.get(title, 'expect_cost_total') and self.config.get(title, 'expect_cost_total') !='0' else 0,
                 'expect_cost_time': self.config.get(title, 'expect_cost_time')  if self.config.get(title, 'expect_cost_time') else 0,
                 'expect_cost_day': self.config.get(title, 'expect_cost_day') if self.config.get(title, 'expect_cost_day') else 0,
                 'request': self.config.get(title, 'request') if self.config.get(title,'request') else '',
                }
    #新增ingroup
        PARAMS['inGroup'] = self.config.get(title, 'inGroup') if self.config.has_option(title, "inGroup") else 255

        PARAMS['vlang'] = [ split(i,',') for i in split(self.config.get(title, 'vlang'),';') if i] if self.config.has_option(title, "vlang") else []

    #修改mpls两层
        PARAMS['mplsg'] = [split(i, ',') for i in split(self.config.get(title, 'mplsg'), ';') if i] if self.config.has_option(title, "mplsg") else []

    #新增mpls
        #PARAMS['mplsg'] = [
            #item.strip()
            #for item in
            #str(self.config.get(title, 'mplsg')).split(';')
            #if item.strip()  # 过滤掉空字符串和空白项
            #] if self.config.has_option(title, "mplsg") else []

    ###兼容原先不支持sni的配置，
        PARAMS['expect_sniNumber'] = self.config.get(title, 'expect_sniNumber') if self.config.has_option(title, "expect_sniNumber") and self.config.get(title, 'expect_sniNumber') != '0' else 0
        PARAMS['expect_httpsPercent'] =  self.config.get(title, 'expect_httpsPercent') if self.config.has_option(title, "expect_httpsPercent") else 0
        PARAMS['expect_notHttps'] = self.config.get(title, 'expect_notHttps') if self.config.has_option(title, "expect_notHttps") else 0
        PARAMS['serviceType'] =  self.config.get(title, 'servicetype') if self.config.has_option(title, "servicetype")  else 0

    ###新增组合规则优先级
        PARAMS['pri'] = self.config.get(title, 'pri') if self.config.has_option(title, "pri") else 0


        return PARAMS


    def setR3(self,title,option,value=None):
        # 用 value is not None 判断而不是 if value：数值 0 是合法配置值，
        # 旧写法会把 0 当成“未设置”而写入空字符串，导致 int('') 报错。
        if value is not None:
            self.config.set(title, option, str(value))
        else:
            self.config.set(title, option, str())
        with open(os.path.join(BASE_DIR, "%s.ini"%self.configName), 'w', encoding='utf-8') as f:
            self.config.write(f)


    def getMirror(self,title):
        PARAMS = {'percent': self.config.get(title, 'percent'),
                  'outgroup_id': self.config.get(title, 'outgroup_id'), }
        return PARAMS

    def getAlarm(self,title):
        PARAMS = {'total_percent': self.config.get(title, 'total_percent'),
                  'day_percent': self.config.get(title, 'day_percent'),
                  'time_percent': self.config.get(title, 'time_percent'), }
        return PARAMS

    def getSni(self,title):
        PARAMS = {'serviceType': self.config.get(title, 'serviceType'),
                  'sniNumber': self.config.get(title, 'sniNumber'),
                  'httpsPercent': self.config.get(title, 'httpsPercent'),
                  'notHttps': self.config.get(title, 'notHttps'),}
        return PARAMS

    def getRuleNumber(self, title):
        PARAMS = {'total': self.config.get(title, 'total'),
                  'forward': self.config.get(title, 'forward'),
                  'drop': self.config.get(title, 'drop'),
                  'alarm': self.config.get(title, 'alarm'),
                  'mirror': self.config.get(title, 'mirror'),}
        return PARAMS

    def getSniRule(self,title='rule'):
        PARAMS = {'operate': self.config.get(title, 'operate'),
                 'expect_code': self.config.get(title, 'expect_code'),
                 'serviceType':self.config.get(title, 'serviceType') if self.config.has_option(title, "serviceType") else 0,
                 'sniG': [ split(i,',') for i in split(self.config.get(title, 'sniG'),';') if i],
                 'request': self.config.get(title, 'request') if self.config.get(title,'request') else 0,
                }
        return PARAMS

class confPacket:
    def __init__(self,configName):
        self.config = configparser.ConfigParser()
        with open(os.path.join(BASE_DIR, "%s.ini"%configName), 'r', encoding='utf-8') as f:
            self.config.read_file(f)
        self.inner_outer = ['gre','ipinip','gtp','l2tp'] #存在内外层
    def getPacket(self,title='packet'):
        PARAMS = {'v4v6':self.config.get(title, 'v4v6'),
                 'sip': split(self.config.get(title, 'sip'),','),
                  'dip': split(self.config.get(title, 'dip'),','),
                  'proto':  self.config.get(title, 'proto'),
                  'sport': [int(i) for i in split(self.config.get(title, 'sport'),',') if i],
                  'dport': [int(i) for i in split(self.config.get(title, 'dport'),',') if i ],
                  'pkt_type': self.config.get(title, 'pkt_type'),
                  'pkt_count': int(self.config.get(title, 'pkt_count')),
                  'raw': self.config.get(title, 'raw'),
                  'raw_offset': int(self.config.get(title, 'raw_offset')),
                  'pkt_len': int(self.config.get(title, 'pkt_len')),
                  'save_name': self.config.get(title, 'save_name')
                  }
        if PARAMS['pkt_type'].lower() in self.inner_outer:
            PARAMS['out_sip'] = self.config.get(title, 'out_sip')
            PARAMS['out_dip'] = self.config.get(title, 'out_dip')
            PARAMS['out_v4v6'] = self.config.get(title, 'out_v4v6')
        if self.config.has_option(title,"vlanid"):
            PARAMS['vlanid'] = self.config.get(title,"vlanid")
        else:
            PARAMS['vlanid'] = "100,200"
        if self.config.has_option(title,"mplslabel"):
            PARAMS['mplslabel'] = self.config.get(title,"mplslabel")
        else:
            PARAMS['mplslabel'] = "300,400"
        try:
            if self.config.get(title, 'proto').lower() == 'tcp':
                PARAMS['tcpflag'] = self.config.get(title, 'tcpflag')[:-1] if str(self.config.get(title, 'tcpflag')).endswith(',') else self.config.get(title, 'tcpflag')
        except:
            pass
        return PARAMS
