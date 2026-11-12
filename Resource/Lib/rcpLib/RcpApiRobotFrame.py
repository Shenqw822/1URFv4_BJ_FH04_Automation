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


import RcpApi

class RcpApiRobotFrame(RcpApi.RcpApi):
    """
    提供RCP接口
    """
    def __init__(self,host,port=6666,rcp_ip="192.168.11.128"):
        RcpApi.RcpApi.__init__(self,host,port,rcp_ip)


if __name__ == "__main__":
    a = RcpApiRobotFrame("192.168.11.111")
    a.auther_user("sysadmin", "sysadmin", 0)