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
import os
import ipaddress


import rcp_packet_data
import rcp_basic
import ssl
import time
import datetime
import test



code_dict = {
    "add" : {"request":"0000","respond":"0001"},
    "change" : {"request":"0100","respond":"0101"},
    "del":{"request":"0200","respond":"0201"},
    "query":{"request":"0300","respond":"0301"},
    "sampling":{"request":"0400","respond":"0401"},
    "alarm":{"request":"0500","respond":"0501"},
}
comFormatAddRuleid = re.compile("^(\S{2})(\S{4})(\S{2})(\S{8})(\S{8})(\S{8})(\S{8})",re.VERBOSE) #7个group
comFormatNoRuleid = re.compile("^(\S{2})(\S{4})(\S{2})(\S{8})(\S{8})(\S{8})",re.VERBOSE) #6个group

class RcpApi:
    """
    创建rcp对应的api接口，提供robot frame调用
    """

    def __init__(self, hostip,port=1000,deviceId=0,sslSwitch=0):
        """
        :param hostip:D设备IP
        :param port: rcp端口,默认60114
        """
        self.hostip = hostip
        self.port = port
        self.conn = self._connect(sslSwitch)
        self.deviceId = deviceId
        self.messId = 0
    def _connect(self,sslSwitch):
        """建立TCP链接
        :param ssl 1:开启ssl,0:关闭ssl，默认关闭
        """
        conn = socket.socket(type=socket.SOCK_STREAM)
        if sslSwitch:
            sk = ssl.wrap_socket(conn, keyfile='cerent/client.key', certfile='cerent/client.crt', cert_reqs=ssl.CERT_REQUIRED, ca_certs='cerent/ca.crt')
            sk.connect((self.hostip, self.port))
            # print(sk.getpeercert())
            return sk
        else:
            conn.connect((self.hostip, self.port))
            return conn

    def _send_message(self, data):
        """
        对设备发送rcp消息
        :param data: 发送的数据
        :return:返回接收的结果
        """
        try:
            print("发送报文:"+ str(binascii.hexlify(data),encoding="utf-8"))
            self.conn.send(data)
            self.conn.settimeout(30)  ##测超长
            time.sleep(0.01)
            recv = self.conn.recv(20480)
        except socket.timeout:
            print("设备未给影响")
            return b'1'
        return recv

    def cli_time_epoc_switchRcp(self,time1,format=0,interval_time=0):
        """
        设备时间和unix时间相互转换，并且增加上间隔时间
        :param time1: 要不unix，要不就是设备系统时间
        :param format:0:返回设备时间格式，1返回unix时间
        :param interval_time: 以秒为单位，在time1的基础上增加该时长
        :return:
        """
        if '-' in str(time1):
            time_get = datetime.datetime.strptime("%s" % time1, "%Y.%m.%d-%H:%M:%S")
            time1_unix = time.mktime(time_get.timetuple())
            time1_unix_interval = time1_unix + int(interval_time)
        else:
            time1_unix_interval = time1 + int(interval_time)
        if not format:
            time2 = datetime.datetime.fromtimestamp(time1_unix_interval)
            device_time = time2.strftime("%Y.%m.%d-%H:%M:%S")
            return device_time
        else:
            return time1_unix_interval

    # def addRule(self,expectRespondCode,pro=("tcp",255),sipGroup=[["192.168.1.1/24",1,2]],dipGroup=[["192.168.1.1/24",1,2]],totalNum=0,dayNum=0,startTime=0,endTime=0,deviceId=0):
    #     """
    #     :param messType: 2B
    #         0x0000  新增放行请求
    #         0x0001  新增放行应答
    #     :param returnCode:  1B 返回码，请求时设置为0
    #     :param deviceId: 4B 设备ID,不携带默认全局，一般不携带
    #     :param pro: [pro:1B,proMask:1B]
    #     :param changeFlag: 1B,0:Ip组内新增源目的三元组;1:表示删减;2:重新下发
    #     :param sip:[v4:4B,v4Mask:2B]、[v6:16B,v4Mask:2B]
    #     :param dip:[v4:4B,v4Mask:2B]、[v6:16B,v4Mask:2B]
    #     :param sport:[start:2B,end:2B]
    #     :param dport:[start:2B,end:2B]
    #     :param totalNum:8B,0:不限量
    #     :param dayNum:8B,0:不限量
    #     :param startTime:8B
    #     :param endTime:8B
    #     :return:questMesaage|expectRespondMessage|exactRespondMessage|RuleId
    #     """
    #     self.messId += 1
    #     requestMessType = '0000'
    #     respondMessType = '0001'
    #     rcpBaseClass = rcp_basic.RcpBasic()
    #     rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(pro,sipGroup,dipGroup,totalNum,dayNum,startTime,endTime)
    #     rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11)
    #     pktLen = len(rcpBody) + len(rcpHeaderNoUse)
    #     deviceId = deviceId if deviceId else self.deviceId
    #     rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,messId=self.messId)
    #     requestMessageList = rcpHeader + rcpBody
    #     requestMessage = rcpBaseClass.data_format_change(requestMessageList)
    #     respondRec = self._send_message(requestMessage)
    #     respondRecHex = str(binascii.hexlify(respondRec),encoding="utf-8")
    #     groupRe = comFormatAddRuleid.match(respondRecHex)
    #     respondRuleIdHex = groupRe.group(7)
    #     respondRuleIdDec = int(respondRuleIdHex,16)
    #     expectRespondMessage = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,20,respondRuleIdDec,messId=self.messId)
    #     return "".join(rcpBody).lower(),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),respondRuleIdDec,
    #
    # def modifyRule(self,modifyType,ruleId,expectRespondCode,pro=("tcp",255),sipGroup=[["192.168.1.1/24",1,2]],dipGroup=[["192.168.1.1/24",1,2]],totalNum=0,dayNum=0,startTime=0,endTime=0,deviceId=0):
    #     """
    #     :param messType: 2B
    #         0x0100  变更请求
    #         0x0101  变更应答
    #     :param modifyType:1B,0:Ip组内新增源目的三元组;1:表示删减;2:重新下发
    #     :param ruleId:修改规则ID
    #     :param returnCode:  1B 返回码，请求时设置为0
    #     :param deviceId: 4B 设备ID,不携带默认全局，一般不携带
    #     :param pro: [pro:1B,proMask:1B]
    #     :param changeFlag: 1B,0:Ip组内新增源目的三元组;1:表示删减;2:重新下发
    #     :param sip:[v4:4B,v4Mask:2B]、[v6:16B,v4Mask:2B]
    #     :param dip:[v4:4B,v4Mask:2B]、[v6:16B,v4Mask:2B]
    #     :param sport:[start:2B,end:2B]
    #     :param dport:[start:2B,end:2B]
    #     :param totalNum:8B,0:不限量
    #     :param dayNum:8B,0:不限量
    #     :param startTime:8B
    #     :param endTime:8B
    #     :return:
    #     """
    #     self.messId += 1
    #     requestMessType = '0100'
    #     respondMessType = '0101'
    #     rcpBaseClass = rcp_basic.RcpBasic()
    #     rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(pro,sipGroup,dipGroup,totalNum,dayNum,startTime,endTime,modifyType)
    #     rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11,ruleId)
    #     pktLen = len(rcpBody) + len(rcpHeaderNoUse)
    #     deviceId = deviceId if deviceId else self.deviceId
    #     rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,ruleId,messId=self.messId)
    #     requestMessageList = rcpHeader + rcpBody
    #     requestMessage = rcpBaseClass.data_format_change(requestMessageList)
    #     respondRec = self._send_message(requestMessage)
    #     respondRecHex = str(binascii.hexlify(respondRec), encoding="utf-8")
    #     groupRe = comFormatNoRuleid.match(respondRecHex)
    #     expectRespondMessage = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,16,messId=self.messId)
    #     return str(binascii.hexlify(requestMessage),encoding="utf-8").lower(),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),ruleId

    def addRule(self,expectRespondCode,sipGroup=[["192.168.1.1/24",1,2,"tcp",255]],dipGroup=[["192.168.1.1/24",1,2,"tcp",255]],vlanGroup=[[1,2]], GroupedPri=0,GaPri=0,GbPri=0,totalNum=0,dayNum=0,startTime=0,endTime=0,ipFlag=1,deviceId=0):
        """
        :param messType: 2B
            0x0000  新增放行请求
            0x0001  新增放行应答
        :param returnCode:  1B 返回码，请求时设置为0
        :param deviceId: 4B 设备ID,不携带默认全局，一般不携带
        :param sip:[v4:4B,v4Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]
        :param dip:[v4:4B,v4Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]
        :param totalNum:8B,0:不限量
        :param dayNum:8B,0:不限量
        :param startTime:8B
        :param endTime:8B
        :param ipFlag 0:v4,1:v6 2:v4/v6
        :return:questMesaage|expectRespondMessage|exactRespondMessage|RuleId
        """
        self.messId += 1
        requestMessType = '0000'
        respondMessType = '0001'
        rcpBaseClass = rcp_basic.RcpBasic()
        #rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,totalNum,dayNum,startTime,endTime,ipFlag=ipFlag)
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,self.cli_time_epoc_switchRcp(startTime,1),self.cli_time_epoc_switchRcp(endTime,1),ipFlag=ipFlag)
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11)
        pktLen = len(rcpBody) + len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,messId=self.messId)
        requestMessageList = rcpHeader + rcpBody
        requestMessage = rcpBaseClass.data_format_change(requestMessageList)
        respondRec = self._send_message(requestMessage)
        respondRecHex = str(binascii.hexlify(respondRec),encoding="utf-8")
        groupRe = comFormatAddRuleid.match(respondRecHex)
        respondRuleIdHex = groupRe.group(7)
        respondRuleIdDec = int(respondRuleIdHex,16)
        expectRespondMessage = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,20,respondRuleIdDec,messId=self.messId)
        # print(rcpBody)
        # print("".join(rcpBody).lower())
        # print(''.join(expectRespondMessage).lower())
        # print(str(binascii.hexlify(respondRec),encoding="utf-8").lower())
        # print(respondRuleIdDec)
        # return 1,1,1,1

        return str(binascii.hexlify(rcpBaseClass.data_format_change(rcpBody)),encoding="utf-8"),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),respondRuleIdDec

    def modifyRule(self,modifyType,ruleId,expectRespondCode,sipGroup=[["192.168.1.1/24",1,2,"tcp",255]],dipGroup=[["192.168.1.1/24",1,2,"tcp",255]],totalNum=0,dayNum=0,startTime=0,endTime=0,ipFlag=1,deviceId=0):
        """
        :param messType: 2B
            0x0100  变更请求
            0x0101  变更应答
        :param modifyType:1B,0:Ip组内新增源目的三元组;1:表示删减;2:重新下发
        :param ruleId:修改规则ID
        :param returnCode:  1B 返回码，请求时设置为0
        :param deviceId: 4B 设备ID,不携带默认全局，一般不携带
        :param sip:[v4:4B,v4Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]
        :param dip:[v4:4B,v4Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]
        :param totalNum:8B,0:不限量
        :param dayNum:8B,0:不限量
        :param startTime:8B
        :param endTime:8B
        :param ipFlag 0:v4,1:v6,2:v4/v6
        :return:
        """
        self.messId += 1
        requestMessType = '0100'
        respondMessType = '0101'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,totalNum,dayNum,startTime,endTime,modifyType,ipFlag)
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11,ruleId)
        pktLen = len(rcpBody) + len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,ruleId,messId=self.messId)
        requestMessageList = rcpHeader + rcpBody
        requestMessage = rcpBaseClass.data_format_change(requestMessageList)
        respondRec = self._send_message(requestMessage)
        respondRecHex = str(binascii.hexlify(respondRec), encoding="utf-8")
        groupRe = comFormatNoRuleid.match(respondRecHex)
        expectRespondMessage = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,16,messId=self.messId)
        return str(binascii.hexlify(requestMessage),encoding="utf-8").lower(),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),ruleId

    def delRule(self,ruleId,expectRespondCode,deviceId=0):
        """
            0x0200  删除请求
            0x0201  删除应答
        :param ruleId: 删除规则ID
        :return:questMesaage|expectRespondMessage|exactRespondMessage|RuleId
        """
        self.messId += 1
        requestMessType = '0200'
        respondMessType = '0201'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11,ruleId)
        pktLen = len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,ruleId,messId=self.messId)
        requestMessage = rcpBaseClass.data_format_change(rcpHeader)
        respondRec = self._send_message(requestMessage)
        respondRecHex = str(binascii.hexlify(respondRec), encoding="utf-8")
        groupRe = comFormatNoRuleid.match(respondRecHex)
        expectRespondMessage = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,16,messId=self.messId)
        return str(binascii.hexlify(requestMessage),encoding="utf-8").lower(),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),ruleId

    def queryRule(self,ruleId,expectRespondCode,expectRuleBody,expectCostTotal,expectCostDayTotal,expectCostTime,deviceId=0):
        """
            0x0300  查询请求
            0x0301  查询应答
        :param ruleId: 删除规则ID
        :return:
        """
        self.messId += 1
        requestMessType = '0300'
        respondMessType = '0301'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11,ruleId)
        pktLen = len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,ruleId,messId=self.messId)
        requestMessage = rcpBaseClass.data_format_change(rcpHeader)
        respondRec = self._send_message(requestMessage)
        expectRespondsuf = rcp_packet_data.RcpPacketData().queryRuleRespondSuf(expectCostTotal,expectCostDayTotal,expectCostTime)
        delHeaderLen = len(expectRuleBody+"".join(expectRespondsuf))
        expectRespondHeadr = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,20+delHeaderLen//2,ruleId,messId=self.messId)
        expectRespondMessage = "".join(expectRespondHeadr)+expectRuleBody+"".join(expectRespondsuf)
        expectRespondMessage04 = rcpBaseClass.rcp_header(respondMessType,'04',deviceId,pktLen,ruleId,messId=self.messId)

        if str(expectRespondCode) !='04':
            return str(binascii.hexlify(requestMessage),encoding="utf-8"),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),ruleId
        else:
            return str(binascii.hexlify(requestMessage), encoding="utf-8"), ''.join(expectRespondMessage04).lower(), str(
                binascii.hexlify(respondRec), encoding="utf-8").lower(),ruleId

    def samplingMirr(self,expectRespondCode,samplingPercent,outgroupId,deviceId=0):
        """

        :param deviceId:
        :param expectRespondCode:
        :param samplingPercent:
        :param outgroupId:
        :return:
        """
        self.messId += 1
        requestMessType = '0400'
        respondMessType = '0401'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11)
        rcpBody = rcp_packet_data.RcpPacketData().samplingRule(samplingPercent,outgroupId)
        pktLen = len(rcpHeaderNoUse+rcpBody)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, pktLen,messId=self.messId)
        requestMessage = rcpBaseClass.data_format_change(rcpHeader+rcpBody)
        respondRec = self._send_message(requestMessage)
        expectRespond = rcpBaseClass.rcp_header(respondMessType, expectRespondCode, deviceId, pktLen-4,messId=self.messId)

        return str(binascii.hexlify(requestMessage), encoding="utf-8"), ''.join(expectRespond).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),0

    def alarmSet(self, expectRespondCode, totalNumAlarmPercent,dayNumAlarmPercent,totalTimePercent,deviceId=0):
        """

        :param deviceId:
        :param expectRespondCode:
        :param samplingPercent:
        :param outgroupId:
        :return:
        """
        self.messId += 1
        requestMessType = '0500'
        respondMessType = '0501'
        rcpBaseClass = rcp_basic.RcpBasic()
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11)
        rcpBody = rcp_packet_data.RcpPacketData().alarmSet(totalNumAlarmPercent,dayNumAlarmPercent,totalTimePercent)
        pktLen = len(rcpHeaderNoUse+rcpBody)
        rcpHeader = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, pktLen,messId=self.messId )
        requestMessage = rcpBaseClass.data_format_change(rcpHeader + rcpBody)
        respondRec = self._send_message(requestMessage)
        expectRespond = rcpBaseClass.rcp_header(respondMessType, expectRespondCode, deviceId, pktLen-4,messId=self.messId)

        return str(binascii.hexlify(requestMessage), encoding="utf-8"), ''.join(expectRespond).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),0

    def dropRule(self,expectRespondCode,sipGroup=[["192.168.1.1/24",1,2,"tcp",255]],dipGroup=[["192.168.1.1/24",1,2,"tcp",255]],vlanGroup=[[1,2]], GroupedPri=0,GaPri=0,GbPri=0,totalNum=0,dayNum=0,startTime=0,endTime=0,ipFlag=1,deviceId=0):
        """
        :param messType: 2B
            0x0600  新增阻断请求
            0x0601  新增阻断应答
        :param returnCode:  1B 返回码，请求时设置为0
        :param deviceId: 4B 设备ID,不携带默认全局，一般不携带
        :param sip:[v4:4B,v4Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]
        :param dip:[v4:4B,v4Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]
        :param totalNum:8B,0:不限量
        :param dayNum:8B,0:不限量
        :param startTime:8B
        :param endTime:8B
        :return:
        :return:questMesaage|expectRespondMessage|exactRespondMessage|RuleId
        """
        self.messId += 1
        requestMessType = '0600'
        respondMessType = '0601'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,startTime,endTime,ipFlag=ipFlag)
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11)
        pktLen = len(rcpBody) + len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,messId=self.messId)
        requestMessageList = rcpHeader + rcpBody
        requestMessage = rcpBaseClass.data_format_change(requestMessageList)
        respondRec = self._send_message(requestMessage)
        respondRecHex = str(binascii.hexlify(respondRec),encoding="utf-8")
        groupRe = comFormatAddRuleid.match(respondRecHex)
        respondRuleIdHex = groupRe.group(7)
        respondRuleIdDec = int(respondRuleIdHex,16)
        expectRespondMessage = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,20,respondRuleIdDec,messId=self.messId)
        return "".join(rcpBody).lower(),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),respondRuleIdDec,

    def queryRuleNum(self, expectRespondCode, expectAllRule, expectFxRule, expectZdRule,alarm,mirr,deviceId=0):
        self.messId += 1
        requestMessType = '0302'
        respondMessType = '0303'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11)
        pktLen = len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, pktLen, messId=self.messId)
        requestMessage = rcpBaseClass.data_format_change(rcpHeader)
        respondRec = self._send_message(requestMessage)
        expectRespondsuf = rcp_packet_data.RcpPacketData().queryRuleNumRespond(expectAllRule, expectFxRule,
                                                                               expectZdRule,alarm,mirr)
        delHeaderLen = len( "".join(expectRespondsuf))
        expectRespondHeadr = rcpBaseClass.rcp_header(respondMessType, expectRespondCode, deviceId,
                                                     pktLen + delHeaderLen//2, messId=self.messId)
        expectRespondMessage = "".join(expectRespondHeadr) + "".join(expectRespondsuf)
        return str(binascii.hexlify(requestMessage), encoding="utf-8"), ''.join(expectRespondMessage).lower(), str(
            binascii.hexlify(respondRec), encoding="utf-8").lower(), 0

    def to_show_hexdump(self,data):
        """
        把对应的数据显示成 每行4字节的形式
        :param data: 数据
        :return:25 03 03 38
                00 00 00 04
                00 00 23 01
        """
        c = re.findall(r'\w{2}', str(data))
        j = 0
        hang = ''
        for i in c:
            j += 1
            k = i + ' '
            hang += k
            if j == 4:
                j = 0
                hang += '\r\n'

        return hang

    def close(self):
        """
        关闭socket链接
        :return:
        """
        self.conn.close()

    def pwd(self):
        print(test.BASE_DIR)


def generate_ipv4(start_ip: str, step: int, n: int) -> str:
    """
    生成从起始IPv4地址开始，按照步伐 step 递增 n 次后的 IPv4 地址。

    :param start_ip: 起始IPv4地址（如 "192.168.1.1"）
    :param step: 每次递增的步长（正整数）
    :param n: 递增的次数（正整数）
    :return: 第 n 个递增后的 IPv4 地址字符串
    """
    try:
        ip = ipaddress.IPv4Address(start_ip)
        new_ip = int(ip) + step * n
        return str(ipaddress.IPv4Address(new_ip))
    except ipaddress.AddressValueError:
        return "Invalid IPv4 address format"
    except ValueError:
        return "IPv4 address out of valid range (0.0.0.0 - 255.255.255.255)"


def generate_ipv6(start_ip: str, step: int, n: int) -> str:
    """
    生成从起始IPv6地址开始，按照步伐 step 递增 n 次后的 IPv6 地址。

    :param start_ip: 起始IPv6地址（如 "2001:0db8::1"）
    :param step: 每次递增的步长（正整数）
    :param n: 递增的次数（正整数）
    :return: 第 n 个递增后的 IPv6 地址字符串
    """
    try:
        ip = ipaddress.IPv6Address(start_ip)
        new_ip = int(ip) + step * n
        return str(ipaddress.IPv6Address(new_ip))
    except ipaddress.AddressValueError:
        return "Invalid IPv6 address format"
    except ValueError:
        return "IPv6 address out of valid range"


if __name__ == "__main__":
    # a = RcpApi('192.168.11.111')
    # e,f,g,h = a.samplingMirr('01',10,1)
    # print(f==g)
    a = RcpApi("192.168.150.94",deviceId=0,sslSwitch=0)
    #测试add增加 0=v4，1=v6，2=v4/v6

    ##测试v4优先级
    # sip = "1.1.1.0"
    # dip = "2.2.2.0"
    # for i in range(0,1):
    #     sipGroup_ALL = []
    #     for j in range(0,7000):
    #         sip_N = generate_ipv4(sip,8,j)
    #     #print( sip_N)
    #         sip_mask = f"%s/30"%sip_N
    #     #print(sip_mask)
    #         sipGroup_ALL.append([sip_mask,1001,1001,0,0])
    #     #sipGroup = [[sip_mask,1001,1001,0,0]]
    #
    #     dip= f'2.2.2.0/32'
    #     dipGroup = [[dip,1002,1002,0,0]]
    #     Grouped_pri = 1
    #     Ga_pri = 1
    #     Gb_pri = 1
    #     request,expectResult,result,ruleid = a.addRule("01",sipGroup_ALL,dipGroup,[],Grouped_pri,Ga_pri,Gb_pri,0,0,0,0,0)  #129
    #print(sipGroup_ALL)

    #测试v6优先级
    sip = "1000::"
    dip = "2000:"
    for i in range(0,1):
        sipGroup_ALL = []
        for j in range(0,7000):
            sip_N = generate_ipv6(sip,32,j)
        #print( sip_N)
            sip_mask = f"%s/123"%sip_N
        #print(sip_mask)
            sipGroup_ALL.append([sip_mask,0,0,0,0])
        #sipGroup = [[sip_mask,1001,1001,0,0]]

        dip= f'2000::/128'
        dipGroup = [[dip,0,0,0,0]]
        Grouped_pri = 26
        Ga_pri = 10
        Gb_pri = 10
        request,expectResult,result,ruleid = a.addRule("01",sipGroup_ALL,dipGroup,[],Grouped_pri,Ga_pri,Gb_pri,0,0,0,0,1)  #129
        #测试阻断
        # request, expectResult, result, ruleid = a.dropRule("01", sipGroup_ALL, dipGroup, [], Grouped_pri, Ga_pri, Gb_pri,
        #                                                   0, 0, 0, 0, 1)  # 129
        print(request)

    # #print(sipGroup_ALL)



    # a.delRule(1, '01')
    #测试add增加 0=v4，1=v6，2=v4/v6
    # request,expectResult,result,ruleid = a.addRule("01",[['0.0.0.0/0',0,0,0,0]],[['2.2.2.2/24',2,2,"tcp",255]],0,0,0,0,0)  #129
    # request, expectResult, result, ruleid = a.addRule("01",[['3.3.3.3/24',3,3,'sctp',0]],[['0.0.0.0/0',5,5,0,0]],0,0,0,0,0) #130
    # request, expectResult, result, ruleid = a.addRule("01",[['5.5.5.5/24',5,5,'udp',0]],[['6.6.6.6/24',7,9,0,0]],0,0,0,0,0) #131
    # request, expectResult, result, ruleid = a.modifyRule(0,129,'01',[['7.7.7.7/24',1,1,'tcp',255]],[],0,0,0,0,0) #129_add
    # request, expectResult, result, ruleid = a.modifyRule(0, 130, '01', [], [['8.8.8.8/24',2,2,'udp',255]], 0, 0, 0, 0, 0) #130_add
    # request, expectResult, result, ruleid = a.modifyRule(1, 129, '01', [['0.0.0.0/0', 0, 0, 0, 0]], [['2.2.2.2/24', 2, 2, 'tcp', 255]], 0, 0, 0, 0, 0)#129_del
    # request, expectResult, result, ruleid = a.modifyRule(1,130,"01", [['3.3.3.3/24', 3, 3, 'sctp', 0]], [['0.0.0.0/0', 5, 5, 0, 0]], 0, 0, 0, 0, 0)  # 130_del
    # request, expectResult, result, ruleid =a.modifyRule(2, 131, "01", [['9.9.9.9/24', 9, 9, 'sctp', 0]], [['10.10.10.10/24', 0, 0, 0, 0]], 0, 0, 0, 0, 0)  # 131_readd
    # request, expectResult, result, ruleid = a.delRule(129,'01')
    # request, expectResult, result, ruleid = a.delRule(130,'01')
    # request, expectResult, result, ruleid = a.delRule(131,'01')
    # print(expectResult == result)

    # 测试add增加1=v6，2=v4/v6
    # request, expectResult, result, ruleid = a.addRule("01", [['0::0/0', 0, 0, 0, 0]], [['2::2/124', 2, 2, "tcp", 255]], 0, 0, 0, 0, 1)  # 129
    # request, expectResult, result, ruleid = a.addRule("01", [['3::3/124', 3, 3, 'sctp', 0]], [['0::0/0', 5, 5, 0, 0]], 0, 0, 0, 0, 1)  # 130
    # request, expectResult, result, ruleid = a.addRule("01", [['5::5/124', 5, 5, 'udp', 0]], [['6::6/124', 7, 9, 0, 0]], 0, 0, 0, 0, 1)  # 131
    # request, expectResult, result, ruleid = a.modifyRule(0, 129, '01', [['7::7/124', 1, 1, 'tcp', 255]], [], 0, 0, 0, 0, 1)  # 129_add
    # request, expectResult, result, ruleid = a.modifyRule(0, 130, '01', [], [['8::/124', 2, 2, 'udp', 255]], 0, 0, 0, 0, 1)  # 130_add
    # request, expectResult, result, ruleid = a.modifyRule(1, 129, '01', [['0::0/0', 0, 0, 0, 0]], [['2::2/124', 2, 2, 'tcp', 255]], 0, 0, 0, 0, 1)  # 129_del
    # request, expectResult, result, ruleid = a.modifyRule(1, 130, "01", [['3::3/124', 3, 3, 'sctp', 0]], [['0::0/0',5, 5, 0, 0]], 0, 0, 0, 0, 1)  # 130_del
    # request, expectResult, result, ruleid = a.modifyRule(2, 131, "01", [['9::9/124', 9, 9, 'sctp', 0]], [['10::10/124', 0, 0, 0, 0]], 0, 0, 0, 0,1)  # 131_readd
    # request, expectResult, result, ruleid = a.delRule(129,"01")
    # request, expectResult, result, ruleid = a.delRule(130,"01")
    # request, expectResult, result, ruleid = a.delRule(131,"01")


    # print(expectResult == result)

    #测试add增加 2=v4/v6
    # request, expectResult, result, ruleid = a.addRule("01",[['1.1.1.1/24',0,0,0,0],['3::3/124', 3, 3, 'sctp', 0]],[['2.2.2.2/24',2,2,"tcp",255]],0,0,0,0,2)  #129
    # request, expectResult, result, ruleid = a.addRule("01",[['5::5/124', 5, 5, 'udp', 0]],[['6::6/124', 7, 9, 0, 0]],0,0,0,0,2) #130
    # request, expectResult, result, ruleid = a.addRule("01",[['3.3.3.3/24',3,3,'sctp',0],['5.5.5.5/24',5,5,'udp',0]],[['6.6.6.6/24',7,9,0,0]],0,0,0,0,2) #131
    # request, expectResult, result, ruleid = a.modifyRule(0,129,'01',[['7.7.7.7/24',1,1,'tcp',255]],[],0,0,0,0,2) #129_add
    # request, expectResult, result, ruleid = a.modifyRule(0, 130, '01', [['9::9/124', 9, 9, 'sctp', 0]], [['8.8.8.8/24',2,2,'udp',255]], 0, 0, 0, 0, 2) #130_add
    # request, expectResult, result, ruleid = a.modifyRule(1, 129, '01', [['1.1.1.1/24', 0, 0, 0, 0]], [['2.2.2.2/24', 2, 2, 'tcp', 255]], 0, 0, 0, 0, 2)#129_del
    # request, expectResult, result, ruleid = a.modifyRule(1,130,"01", [['5::5/124', 5, 5, 'udp', 0]], [], 0, 0, 0, 0, 2)  # 130_del
    # request, expectResult, result, ruleid = a.modifyRule(2, 131, "01", [['13::13/124', 3, 3, 'sctp', 0]], [['10::10/124', 0, 0, 0, 0]], 0, 0, 0, 0, 2)  # 131_readd
    # request, expectResult, result, ruleid = a.delRule(129,"01")
    # request, expectResult, result, ruleid = a.delRule(130,"01")
    # request, expectResult, result, ruleid = a.delRule(131,"01")
    # print(expectResult)
    # print(result)
    # print(expectResult == result)