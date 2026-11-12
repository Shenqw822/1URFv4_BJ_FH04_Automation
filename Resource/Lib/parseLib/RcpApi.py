#!/bin/bash/env python
#-*- coding:utf-8 -*-
#Author PeiWenPing
#time:2024/1/23:16:47
#email:peiwenping@finslink.com

#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2022/3/7:20:47
# email:peiwenping@finslink.com
"""
function:提供rcp客户端所需要的接口分为如下：
        1.用户认证、建立关闭链接
        2.新建规则
        3.查询规则
        4.删除规则
"""

import socket
import binascii
import re
import time
import DdevieParsePacket

code_dict = {
    "login_out" : {"request":["01","01","48"],"respond":["01","02","04"]},

    "v4_add" : {"request":["02","01","45"],"respond":["02","02","08"]},
    "v6_add" : {"request":["02","01","93"],"respond":["02","02","08"]},
    "tzm_add":{"request":["02","03","150"],"respond":["02","04","08"]},
    "tcp_flag":{"request":["02","21","24"],"respond":["02","22","08"]},
    "group_add_v4_tz":{"request":["02","FE","177"],"respond":["02","FF","08"]},
    "group_add_v6_tz":{"request":["02","FE","225"],"respond":["02","FF","08"]},

    "rule_del": {"request": ["03", "01", "06"], "respond": ["03", "02", "08"]},

    "rule_query_v4": {"request": ["04", "01", "06"], "respond": ["04", "02", "45"]},
    "rule_query_v6": {"request": ["04", "01", "06"], "respond": ["04", "02", "93"]},
    "rule_query_tzm": {"request": ["04", "01", "06"], "respond": ["04", "02", "150"]},
    "rule_query_tcpflag": {"request": ["04", "01", "06"], "respond": ["04", "02", "24"]},
    "rule_query_v4_tzm": {"request": ["04", "01", "06"], "respond": ["04", "02", "177"]},
    "rule_query_v6_tzm": {"request": ["04", "01", "06"], "respond": ["04", "02", "225"]},
    "stream_manage" : {"request": ["05", "01", "08"], "respond": ["05", "02", "04"]},
    "valid_command" : {"request": ["07", "01", "08"], "respond": ["07", "02", "04"]},
    "valid_type": {"request": ["02", "04", "08"], "respond": ["02", "02", "04"]},
}

class RcpApi:
    """
    创建rcp对应的api接口，提供robot frame调用
    """

    def __init__(self, hostip, port=60114):
        """
        :param hostip:D设备IP
        :param port: rcp端口,默认60114
        """
        self.hostip = hostip
        self.port = port
        self.conn = self._connect()
        auth_data = b'\xd1\x11\x01\x01\x00\x00\x000sysadmin\x00\x00\x00\x00\x00\x00\x00\x0048a365b4ce1e322a55ae9017f3daf0c0'
        self.r3_send_message(auth_data)

    def _connect(self):
        """建立TCP链接"""
        conn = socket.socket(type=socket.SOCK_STREAM)
        conn.connect((self.hostip, self.port))
        return conn

    def r3_send_message(self, *data):
        """
        对设备发送rcp消息
        :param data: 发送的数据,当为列表，则多次下发
        :return:返回接收的结果
        """
        recv=[]
        for i in data:
            try:
                print("发送报文:"+ str(binascii.hexlify(i),encoding="utf-8"))

                self.conn.send(i)
                self.conn.settimeout(5)
                time.sleep(1)
                recv.append(self.conn.recv(20480))
            except socket.timeout:
                print("设备未给影响")
                return b'1'
        return recv

    def r3_delete_1_2(self):
        appid1 = b'\xd1\x11\x03\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x01'
        appid2= b'\xd1\x11\x03\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x02'
        self.r3_send_message(appid1)
        self.r3_send_message(appid2)
