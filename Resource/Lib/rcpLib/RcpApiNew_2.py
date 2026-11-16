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
import time

import rcp_packet_data
import rcp_basic
import ssl
import time
import datetime
# from config import CLIENT

# 证书跟随代码目录，避免从仓库根目录运行 RF 时找不到 cerent/
CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cerent')



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
        print(hostip)
    def _connect(self,sslSwitch):
        """建立TCP链接
        :param ssl 1:开启ssl,0:关闭ssl，默认关闭
        """
        conn = socket.socket(type=socket.SOCK_STREAM)
        if sslSwitch:
            sk = ssl.wrap_socket(conn,
                                 keyfile=os.path.join(CERT_DIR, 'client.key'),
                                 certfile=os.path.join(CERT_DIR, 'client.crt'),
                                 cert_reqs=ssl.CERT_REQUIRED,
                                 ca_certs=os.path.join(CERT_DIR, 'ca.crt'))
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
            # print("发送报文:"+ str(binascii.hexlify(data),encoding="utf-8"))
            self.conn.send(data)
            self.conn.settimeout(5)
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
            time1_unix_interval = int(time1_unix) + int(interval_time)
        else:
            time1_unix_interval = int(time1) + int(interval_time)
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
    def addSniRule(self,**kwargs):
        """
        :param messType: 2B
            0x0702  新增放行请求
            0x0703  新增放行应答
        :param returnCode:  1B 返回码，请求时设置为0
        :param deviceId: 4B 设备ID,不携带默认全局，一般不携带
        :param serviceType:1B 业务类型
        :param sniNumber:1B SNI数量
        :return:sniGroup:4*n [[sniLen1,sniValue1],[sniLen2,sniValue2],...]
        """
        expectRespondCode=kwargs['expect_code']
        sniGroup = kwargs['sniG']
        serviceType = kwargs['serviceType']
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0702'
        respondMessType = '0703'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpBody = rcp_packet_data.RcpPacketData().addSniRule(serviceType, sniGroup)
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11)
        pktLen = len(rcpBody) + len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,messId=self.messId)
        requestMessageList = rcpHeader + rcpBody
        requestMessage = rcpBaseClass.data_format_change(requestMessageList)
        respondRec = self._send_message(requestMessage)
        respondRecHex = str(binascii.hexlify(respondRec),encoding="utf-8")
        groupRe = comFormatAddRuleid.match(respondRecHex)
        # respondRuleIdHex = groupRe.group(7)
        respondRuleIdDec = 0
        expectRespondMessage = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,16,respondRuleIdDec,messId=self.messId)
        return str(binascii.hexlify(rcpBaseClass.data_format_change(rcpBody)), encoding="utf-8"), ''.join(
            expectRespondMessage).lower(), str(binascii.hexlify(respondRec), encoding="utf-8").lower(), respondRuleIdDec


    def addRule(self,**kwargs):
        """
        :param messType: 2B
            0x0000  新增放行请求
            0x0001  新增放行应答
        :param returnCode:  1B 返回码，请求时设置为0
        :param deviceId: 4B 设备ID,不携带默认全局，一般不携带
        :param sip:[v4:4B,v4Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]
        :param dip:[v4:4B,v4Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]
        :param limitFlag 0:月限量 1：天限量 2：周限量 10：不限量
        :param totalNum:8B,0:不限量
        :param dayNum:8B,0:不限量
        :param startTime:8B
        :param endTime:8B
        :param ipFlag 0:v4,1:v6 2:v4/v6
        :return:questMesaage|expectRespondMessage|exactRespondMessage|RuleId
        """
        print(f"从int中提取到的信息{kwargs}")
        expectRespondCode=kwargs['expect_code']
        sipGroup = kwargs['sipg']
        dipGroup = kwargs['dipg']
        totalNum = kwargs['total']
        dayNum = kwargs['day']
        startTime = kwargs['starttime']
        endTime = kwargs['endtime']
        inGroup = kwargs['inGroup']
        vlanGroup = kwargs['vlang']
        mplsGroup = kwargs['mplsg']
        if str(kwargs['limit_type']).lower() == 'months' or kwargs['limit_type'] == 0:
            limitFlag = 0
        elif str(kwargs['limit_type']).lower() == 'days':
            limitFlag = 1
        elif str(kwargs['limit_type']).lower() == 'weeks':
            limitFlag = 2
        else:
            limitFlag = 10
        #serviceType = kwargs['serviceType']
        Pri = kwargs['pri']
        if str(kwargs['v4v6']).lower() == 'v4':
            ipFlag = 0
        elif str(kwargs['v4v6']).lower() == 'v6':
            ipFlag = 1
        else:
            ipFlag = 2
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0000'
        respondMessType = '0001'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(
            sipGroup,
            dipGroup,
            inGroup,
            vlanGroup,
            mplsGroup,
            limitFlag,
            Pri,
            totalNum,
            dayNum,
            self.cli_time_epoc_switchRcp(startTime,1),
            self.cli_time_epoc_switchRcp(endTime,1),
            ipFlag=ipFlag
        )
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

    def modifyRule(self,ruleId,**kwargs):
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
        if kwargs['modify_type'].lower() == 'sip':
            modifyType  = 0
        elif kwargs['modify_type'].lower() == 'dip':
            modifyType = 1
        else:
            modifyType = 2
        expectRespondCode = kwargs['expect_code']
        sipGroup = kwargs['sipg']
        dipGroup = kwargs['dipg']
        totalNum = kwargs['total']
        dayNum = kwargs['day']
        startTime = kwargs['starttime']
        endTime = kwargs['endtime']
        inGroup = kwargs['inGroup']
        vlanGroup = kwargs['vlang']
        mplsGroup = kwargs['mplsg']
        if str(kwargs['limit_type']).lower() == 'months' or kwargs['limit_type'] == 0:
            limitFlag = 0
        elif str(kwargs['limit_type']).lower() == 'days':
            limitFlag = 1
        elif str(kwargs['limit_type']).lower() == 'weeks':
            limitFlag = 2
        else:
            limitFlag = 10
        #serviceType = kwargs['serviceType']
        Pri = kwargs['pri']
        if str(kwargs['v4v6']).lower() == 'v4':
            ipFlag = 0
        elif str(kwargs['v4v6']).lower() == 'v6':
            ipFlag = 1
        else:
            ipFlag = 2
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0100'
        respondMessType = '0101'
        rcpBaseClass = rcp_basic.RcpBasic()
        #rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,startTime,endTime,modifyType,ipFlag)
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(
            sipGroup,
            dipGroup,
            inGroup,
            vlanGroup,
            mplsGroup,
            limitFlag,
            Pri,
            totalNum,
            dayNum,
            self.cli_time_epoc_switchRcp(startTime,1),
            self.cli_time_epoc_switchRcp(endTime,1),
            modifyType,
            ipFlag=ipFlag
        )
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

    def queryRulenew(self,ruleid,**kwargs):
        """
            0x0300  查询请求
            0x0301  查询应答
        :param ruleId: 删除规则ID
        :return:
        """
        print(kwargs)
        ruleId = ruleid
        expectRespondCode = kwargs['expect_code']
        expectRuleBody = kwargs['request']
        expectCostTotal = kwargs['expect_cost_total']
        expectCostDayTotal = kwargs['expect_cost_day']
        expectCostTime = kwargs['expect_cost_time']
        expectSniNumber = kwargs['expect_sniNumber']
        expectHttpsPercent = kwargs['expect_httpsPercent']
        expectNotHttps = kwargs['expect_notHttps']
        deviceId = 0
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
        expectRespondsuf = rcp_packet_data.RcpPacketData().queryRuleRespondSuf(expectCostTotal,expectCostDayTotal,expectCostTime,expectSniNumber,expectHttpsPercent,expectNotHttps)
        delHeaderLen = len(expectRuleBody+"".join(expectRespondsuf))
        expectRespondHeadr = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,20+delHeaderLen//2,ruleId,messId=self.messId)
        expectRespondMessage = "".join(expectRespondHeadr)+expectRuleBody+"".join(expectRespondsuf)
        expectRespondMessage04 = rcpBaseClass.rcp_header(respondMessType,'04',deviceId,pktLen,ruleId,messId=self.messId)

        if str(expectRespondCode) !='04':
            return str(binascii.hexlify(requestMessage),encoding="utf-8"),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),ruleId
        else:
            return str(binascii.hexlify(requestMessage), encoding="utf-8"), ''.join(expectRespondMessage04).lower(), str(
                binascii.hexlify(respondRec), encoding="utf-8").lower(),ruleId

    def queryRule(self,ruleId,expectRespondCode,expectRuleBody,expectCostTotal,expectCostDayTotal,expectCostTime,expectSniNumber,expectHttpsPercent,expectNohttps,deviceId=0):
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
        expectRespondsuf = rcp_packet_data.RcpPacketData().queryRuleRespondSuf(expectCostTotal,expectCostDayTotal,expectCostTime,expectSniNumber,expectHttpsPercent,expectNohttps)
        delHeaderLen = len(expectRuleBody+"".join(expectRespondsuf))
        expectRespondHeadr = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,20+delHeaderLen//2,ruleId,messId=self.messId)
        expectRespondMessage = "".join(expectRespondHeadr)+expectRuleBody+"".join(expectRespondsuf)
        expectRespondMessage04 = rcpBaseClass.rcp_header(respondMessType,'04',deviceId,pktLen,ruleId,messId=self.messId)

        if str(expectRespondCode) !='04':
            return str(binascii.hexlify(requestMessage),encoding="utf-8"),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),ruleId
        else:
            return str(binascii.hexlify(requestMessage), encoding="utf-8"), ''.join(expectRespondMessage04).lower(), str(
                binascii.hexlify(respondRec), encoding="utf-8").lower(),ruleId

    def samplingMirr(self,**kwargs):
        """

        :param deviceId:
        :param expectRespondCode:
        :param samplingPercent:
        :param outgroupId:
        :return:
        """
        expectRespondCode = '01'
        samplingPercent = kwargs['percent']
        outgroupId = kwargs['outgroup_id']
        deviceId = 0
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

    def alarmSet(self, **kwargs):
        """

        :param deviceId:
        :param expectRespondCode:
        :param samplingPercent:
        :param outgroupId:
        :return:
        """
        expectRespondCode = '01'
        totalNumAlarmPercent = kwargs['total_percent']
        dayNumAlarmPercent = kwargs['day_percent']
        totalTimePercent = kwargs['time_percent']
        deviceId = self.deviceId
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

    def dropRule(self,**kwargs):
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
        expectRespondCode = kwargs['expect_code']
        sipGroup = kwargs['sipg']
        dipGroup = kwargs['dipg']
        totalNum = kwargs['total']
        dayNum = kwargs['day']
        startTime = kwargs['starttime']
        endTime = kwargs['endtime']
        inGroup = kwargs['inGroup']
        vlanGroup = kwargs['vlang']
        mplsGroup = kwargs['mplsg']
        if str(kwargs['limit_type']).lower() == 'months' or kwargs['limit_type'] == 0:
            limitFlag = 0
        elif str(kwargs['limit_type']).lower() == 'days':
            limitFlag = 1
        elif str(kwargs['limit_type']).lower() == 'weeks':
            limitFlag = 2
        else:
            limitFlag = 10
        serviceType = kwargs['serviceType']
        Pri = kwargs['pri']
        if str(kwargs['v4v6']).lower() == 'v4':
            ipFlag = 0
        elif str(kwargs['v4v6']).lower() == 'v6':
            ipFlag = 1
        else:
            ipFlag = 2
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0600'
        respondMessType = '0601'
        rcpBaseClass = rcp_basic.RcpBasic()
        #rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,startTime,endTime,ipFlag=ipFlag)
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(
            sipGroup,
            dipGroup,
            inGroup,
            vlanGroup,
            mplsGroup,
            limitFlag,
            Pri,
            totalNum,
            dayNum,
            self.cli_time_epoc_switchRcp(startTime,1),
            self.cli_time_epoc_switchRcp(endTime,1),
            ipFlag=ipFlag
        )
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
        print(str(binascii.hexlify(requestMessage),encoding="utf-8").lower())

    def sniSet(self, **kwargs):
        """
        设置sni规则
        :param serviceType: 业务类型编码
        :param sniNumber: SNI数量阈值
        :param httpsPercent: 非HTTPS比例阈值
        :param notHttps: 非HTTPS阈值生效起始量(MByte)
        """
        expectRespondCode = kwargs["expectRespondCode"]
        serviceType = kwargs['serviceType']
        sniNumber = kwargs['sniNumber']
        httpsPercent = kwargs['httpsPercent']
        notHttps = kwargs['notHttps']
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '700'
        respondMessType = '701'
        rcpBaseClass = rcp_basic.RcpBasic()
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11)
        rcpBody = rcp_packet_data.RcpPacketData().addSni(serviceType, sniNumber, httpsPercent,notHttps)
        pktLen = len(rcpHeaderNoUse + rcpBody)
        rcpHeader = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, pktLen, messId=self.messId)
        requestMessage = rcpBaseClass.data_format_change(rcpHeader + rcpBody)
        respondRec = self._send_message(requestMessage)
        expectRespond = rcpBaseClass.rcp_header(respondMessType, expectRespondCode, deviceId, pktLen - 4,
                                                messId=self.messId)

        return str(binascii.hexlify(requestMessage), encoding="utf-8"), ''.join(expectRespond).lower(), str(
            binascii.hexlify(respondRec), encoding="utf-8").lower(), 0

    def queryRuleNum(self, **kwargs):
        expectRespondCode = '01'
        expectAllRule = kwargs['total']
        expectFxRule = kwargs['forward']
        expectZdRule = kwargs['drop']
        alarm = kwargs['alarm']
        mirr = kwargs['mirror']
        deviceId = 0
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

    def validMessType(self, **kwargs):
        """

        :param deviceId:
        :param expectRespondCode:
        :param samplingPercent:
        :param outgroupId:
        :return:
        """
        expectRespondCode = '01'
        totalNumAlarmPercent = kwargs['total_percent']
        dayNumAlarmPercent = kwargs['day_percent']
        totalTimePercent = kwargs['time_percent']
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0700'
        respondMessType = '0701'
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
        
    def addRule_FiveTuple(self,**kwargs):
        """
        :param messType: 2B
            0x0002  新增放行请求(五元组)
            0x0003  新增放行应答(五元组)
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
        expectRespondCode=kwargs['expect_code']
        sipGroup = kwargs['sipg']
        dipGroup = kwargs['dipg']
        totalNum = kwargs['total']
        dayNum = kwargs['day']
        startTime = kwargs['starttime']
        endTime = kwargs['endtime']
        inGroup = kwargs['inGroup']
        vlanGroup = kwargs['vlang']
        mplsGroup = kwargs['mplsg']
        if str(kwargs['limit_type']).lower() == 'months' or kwargs['limit_type'] == 0:
            limitFlag = 0
        elif str(kwargs['limit_type']).lower() == 'days':
            limitFlag = 1
        elif str(kwargs['limit_type']).lower() == 'weeks':
            limitFlag = 2
        else:
            limitFlag = 10
        #serviceType = kwargs['serviceType']
        Pri = kwargs['pri']
        if str(kwargs['v4v6']).lower() == 'v4':
            ipFlag = 0
        elif str(kwargs['v4v6']).lower() == 'v6':
            ipFlag = 1
        else:
            ipFlag = 2
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0002'
        respondMessType = '0003'
        rcpBaseClass = rcp_basic.RcpBasic()
        #rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,self.cli_time_epoc_switchRcp(startTime,1),self.cli_time_epoc_switchRcp(endTime,1),ipFlag=ipFlag)
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(
            sipGroup,
            dipGroup,
            inGroup,
            vlanGroup,
            mplsGroup,
            limitFlag,
            Pri,
            totalNum,
            dayNum,
            self.cli_time_epoc_switchRcp(startTime,1),
            self.cli_time_epoc_switchRcp(endTime,1),
            ipFlag=ipFlag
        )
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11)
        pktLen = len(rcpBody) + len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,messId=self.messId)
        requestMessageList = rcpHeader + rcpBody
        requestMessage = rcpBaseClass.data_format_change(requestMessageList)
        respondRec = self._send_message(requestMessage)
        respondRecHex = str(binascii.hexlify(respondRec),encoding="utf-8")
        print("设备返回的应答数据（十六进制）：", respondRecHex)
        groupRe = comFormatAddRuleid.match(respondRecHex)
        respondRuleIdHex = groupRe.group(7)
        respondRuleIdDec = int(respondRuleIdHex,16)
        expectRespondMessage = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,20,respondRuleIdDec,messId=self.messId)
        print(str(binascii.hexlify(requestMessage),encoding="utf-8").lower())
        # print(rcpBody)
        # print("".join(rcpBody).lower())
        # print(''.join(expectRespondMessage).lower())
        # print(str(binascii.hexlify(respondRec),encoding="utf-8").lower())
        # print(respondRuleIdDec)
        # return 1,1,1,1

        return str(binascii.hexlify(rcpBaseClass.data_format_change(rcpBody)),encoding="utf-8"),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),respondRuleIdDec

    def modifyRule_FiveTuple(self,ruleId,**kwargs):
        """
        :param messType: 2B
            0x0102  变更请求(五元组)
            0x0103  变更应答(五元组)
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
        if kwargs['modify_type'].lower() == 'sip':
            modifyType  = 0
        elif kwargs['modify_type'].lower() == 'dip':
            modifyType = 1
        else:
            modifyType = 2
        expectRespondCode = kwargs['expect_code']
        sipGroup = kwargs['sipg']
        dipGroup = kwargs['dipg']
        totalNum = kwargs['total']
        dayNum = kwargs['day']
        startTime = kwargs['starttime']
        endTime = kwargs['endtime']
        inGroup = kwargs['inGroup']
        vlanGroup = kwargs['vlang']
        mplsGroup = kwargs['mplsg']
        if str(kwargs['limit_type']).lower() == 'months' or kwargs['limit_type'] == 0:
            limitFlag = 0
        elif str(kwargs['limit_type']).lower() == 'days':
            limitFlag = 1
        elif str(kwargs['limit_type']).lower() == 'weeks':
            limitFlag = 2
        else:
            limitFlag = 10
        #serviceType = kwargs['serviceType']
        Pri = kwargs['pri']
        if str(kwargs['v4v6']).lower() == 'v4':
            ipFlag = 0
        elif str(kwargs['v4v6']).lower() == 'v6':
            ipFlag = 1
        else:
            ipFlag = 2
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0102'
        respondMessType = '0103'
        rcpBaseClass = rcp_basic.RcpBasic()
        #rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,startTime,endTime,modifyType,ipFlag)
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(
            sipGroup,
            dipGroup,
            inGroup,
            vlanGroup,
            mplsGroup,
            limitFlag,
            Pri,
            totalNum,
            dayNum,
            self.cli_time_epoc_switchRcp(startTime,1),
            self.cli_time_epoc_switchRcp(endTime,1),
            ipFlag=ipFlag
        )
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

    def delRule_FiveTuple(self,ruleId,expectRespondCode,deviceId=0):
        """
            0x0202  删除请求(五元组)
            0x0203  删除应答(五元组)
        :param ruleId: 删除规则ID
        :return:questMesaage|expectRespondMessage|exactRespondMessage|RuleId
        """
        self.messId += 1
        requestMessType = '0202'
        respondMessType = '0203'
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

    def queryRulenew_FiveTuple(self,ruleid,**kwargs):
        """
            0x0304  查询请求(五元组)
            0x0305  查询应答(五元组)
        :param ruleId: 删除规则ID
        :return:
        """
        ruleId = ruleid
        expectRespondCode = kwargs['expect_code']
        expectRuleBody = kwargs['request']
        expectCostTotal = kwargs['expect_cost_total']
        expectCostDayTotal = kwargs['expect_cost_day']
        expectCostTime = kwargs['expect_cost_time']
        expectSniNumber = kwargs['expect_sniNumber']
        expectHttpsPercent = kwargs['expect_httpsPercent']
        expectNotHttps = kwargs['expect_notHttps']
        deviceId = 0
        self.messId += 1
        requestMessType = '0304'
        respondMessType = '0305'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11,ruleId)
        pktLen = len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,ruleId,messId=self.messId)
        requestMessage = rcpBaseClass.data_format_change(rcpHeader)
        respondRec = self._send_message(requestMessage)
        expectRespondsuf = rcp_packet_data.RcpPacketData().queryRuleRespondSuf(expectCostTotal,expectCostDayTotal,expectCostTime,expectSniNumber,expectHttpsPercent,expectNotHttps)
        delHeaderLen = len(expectRuleBody+"".join(expectRespondsuf))
        expectRespondHeadr = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,20+delHeaderLen//2,ruleId,messId=self.messId)
        expectRespondMessage = "".join(expectRespondHeadr)+expectRuleBody+"".join(expectRespondsuf)
        expectRespondMessage04 = rcpBaseClass.rcp_header(respondMessType,'04',deviceId,pktLen,ruleId,messId=self.messId)

        if str(expectRespondCode) !='04':
            return str(binascii.hexlify(requestMessage),encoding="utf-8"),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),ruleId
        else:
            return str(binascii.hexlify(requestMessage), encoding="utf-8"), ''.join(expectRespondMessage04).lower(), str(
                binascii.hexlify(respondRec), encoding="utf-8").lower(),ruleId

    def alarmSet_FiveTuple(self, **kwargs):
        """
        0x0502  查询请求(五元组)
        0x0503  查询应答(五元组)
        :param deviceId:
        :param expectRespondCode:
        :param samplingPercent:
        :param outgroupId:
        :return:
        """
        expectRespondCode = '01'
        totalNumAlarmPercent = kwargs['total_percent']
        dayNumAlarmPercent = kwargs['day_percent']
        totalTimePercent = kwargs['time_percent']
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0502'
        respondMessType = '0503'
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

    def dropRule_FiveTuple(self,**kwargs):
        """
        :param messType: 2B
            0x0602  新增阻断请求(五元组)
            0x0603  新增阻断应答(五元组)
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
        expectRespondCode = kwargs['expect_code']
        sipGroup = kwargs['sipg']
        dipGroup = kwargs['dipg']
        totalNum = kwargs['total']
        dayNum = kwargs['day']
        startTime = kwargs['starttime']
        endTime = kwargs['endtime']
        inGroup = kwargs['inGroup']
        vlanGroup = kwargs['vlang']
        mplsGroup = kwargs['mplsg']
        #serviceType = kwargs['serviceType']
        if str(kwargs['limit_type']).lower() == 'months' or kwargs['limit_type'] == 0:
            limitFlag = 0
        elif str(kwargs['limit_type']).lower() == 'days':
            limitFlag = 1
        elif str(kwargs['limit_type']).lower() == 'weeks':
            limitFlag = 2
        else:
            limitFlag = 10
        Pri = kwargs['pri']
        if str(kwargs['v4v6']).lower() == 'v4':
            ipFlag = 0
        elif str(kwargs['v4v6']).lower() == 'v6':
            ipFlag = 1
        else:
            ipFlag = 2
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0602'
        respondMessType = '0603'
        rcpBaseClass = rcp_basic.RcpBasic()
        #rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,startTime,endTime,ipFlag=ipFlag)
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(
            sipGroup,
            dipGroup,
            inGroup,
            vlanGroup,
            mplsGroup,
            limitFlag,
            Pri,
            totalNum,
            dayNum,
            self.cli_time_epoc_switchRcp(startTime,1),
            self.cli_time_epoc_switchRcp(endTime,1),
            ipFlag=ipFlag
        )
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

    def addRule_L2(self,**kwargs):
        """
        :param messType: 2B
            0x0010  新增放行请求(L2规则)
            0x0011  新增放行应答(L2规则)
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
        print(kwargs)
        expectRespondCode=kwargs['expect_code']
        sipGroup = kwargs['sipg']
        dipGroup = kwargs['dipg']
        totalNum = kwargs['total']
        dayNum = kwargs['day']
        startTime = kwargs['starttime']
        endTime = kwargs['endtime']
        inGroup = kwargs['inGroup']
        vlanGroup = kwargs['vlang']
        mplsGroup = kwargs['mplsg']
        if str(kwargs['limit_type']).lower() == 'months'or kwargs['limit_type'] == 0:
            limitFlag = 0
        elif str(kwargs['limit_type']).lower() == 'days':
            limitFlag = 1
        elif str(kwargs['limit_type']).lower() == 'weeks':
            limitFlag = 2
        else:
            limitFlag = 10
        #serviceType = kwargs['serviceType']
        Pri = kwargs['pri']
        if str(kwargs['v4v6']).lower() == 'v4':
            ipFlag = 0
        elif str(kwargs['v4v6']).lower() == 'v6':
            ipFlag = 1
        else:
            ipFlag = 2
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0010'
        respondMessType = '0011'
        rcpBaseClass = rcp_basic.RcpBasic()
        #rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,self.cli_time_epoc_switchRcp(startTime,1),self.cli_time_epoc_switchRcp(endTime,1),ipFlag=ipFlag)
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(
            sipGroup,
            dipGroup,
            inGroup,
            vlanGroup,
            mplsGroup,
            limitFlag,
            Pri,
            totalNum,
            dayNum,
            self.cli_time_epoc_switchRcp(startTime,1),
            self.cli_time_epoc_switchRcp(endTime,1),
            ipFlag=ipFlag
        )
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
        print(str(binascii.hexlify(requestMessage),encoding="utf-8").lower())
        # print("".join(rcpBody).lower())
        # print(''.join(expectRespondMessage).lower())
        # print(str(binascii.hexlify(respondRec),encoding="utf-8").lower())
        # print(respondRuleIdDec)
        # return 1,1,1,1

        return str(binascii.hexlify(rcpBaseClass.data_format_change(rcpBody)),encoding="utf-8"),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),respondRuleIdDec

    def modifyRule_L2(self,ruleId,**kwargs):
        """
        :param messType: 2B
            0x0110  变更请求(L2规则)
            0x0111  变更应答(L2规则)
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
        if kwargs['modify_type'].lower() == 'sip':
            modifyType  = 0
        elif kwargs['modify_type'].lower() == 'dip':
            modifyType = 1
        else:
            modifyType = 2
        expectRespondCode = kwargs['expect_code']
        sipGroup = kwargs['sipg']
        dipGroup = kwargs['dipg']
        totalNum = kwargs['total']
        dayNum = kwargs['day']
        startTime = kwargs['starttime']
        endTime = kwargs['endtime']
        inGroup = kwargs['inGroup']
        vlanGroup = kwargs['vlang']
        mplsGroup = kwargs['mplsg']
        if str(kwargs['limit_type']).lower() == 'months'or kwargs['limit_type'] == 0:
            limitFlag = 0
        elif str(kwargs['limit_type']).lower() == 'days':
            limitFlag = 1
        elif str(kwargs['limit_type']).lower() == 'weeks':
            limitFlag = 2
        else:
            limitFlag = 10
        #serviceType = kwargs['serviceType']
        Pri = kwargs['pri']
        if str(kwargs['v4v6']).lower() == 'v4':
            ipFlag = 0
        elif str(kwargs['v4v6']).lower() == 'v6':
            ipFlag = 1
        else:
            ipFlag = 2
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0110'
        respondMessType = '0111'
        rcpBaseClass = rcp_basic.RcpBasic()
        #rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,startTime,endTime,modifyType,ipFlag)
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(
            sipGroup,
            dipGroup,
            inGroup,
            vlanGroup,
            mplsGroup,
            limitFlag,
            Pri,
            totalNum,
            dayNum,
            self.cli_time_epoc_switchRcp(startTime,1),
            self.cli_time_epoc_switchRcp(endTime,1),
            ipFlag=ipFlag
        )
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

    def delRule_L2(self,ruleId,expectRespondCode,deviceId=0):
        """
            0x0210  删除请求(L2规则)
            0x0211  删除应答(L2规则)
        :param ruleId: 删除规则ID
        :return:questMesaage|expectRespondMessage|exactRespondMessage|RuleId
        """
        self.messId += 1
        requestMessType = '0210'
        respondMessType = '0211'
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
        print(str(binascii.hexlify(requestMessage),encoding="utf-8").lower())

    def queryRulenew_L2(self,ruleid,**kwargs):
        """
            0x0310  查询请求(L2规则)
            0x0311  查询应答(L2规则)
        :param ruleId: 删除规则ID
        :return:
        """
        ruleId = ruleid
        expectRespondCode = kwargs['expect_code']
        expectRuleBody = kwargs['request']
        expectCostTotal = kwargs['expect_cost_total']
        expectCostDayTotal = kwargs['expect_cost_day']
        expectCostTime = kwargs['expect_cost_time']
        expectSniNumber = kwargs['expect_sniNumber']
        expectHttpsPercent = kwargs['expect_httpsPercent']
        expectNotHttps = kwargs['expect_notHttps']
        deviceId = 0
        self.messId += 1
        requestMessType = '0310'
        respondMessType = '0311'
        rcpBaseClass = rcp_basic.RcpBasic()
        rcpHeaderNoUse = rcpBaseClass.rcp_header(requestMessType, 0, deviceId, 11,ruleId)
        pktLen = len(rcpHeaderNoUse)
        deviceId = deviceId if deviceId else self.deviceId
        rcpHeader = rcpBaseClass.rcp_header(requestMessType,0,deviceId,pktLen,ruleId,messId=self.messId)
        requestMessage = rcpBaseClass.data_format_change(rcpHeader)
        respondRec = self._send_message(requestMessage)
        expectRespondsuf = rcp_packet_data.RcpPacketData().queryRuleRespondSuf(expectCostTotal,expectCostDayTotal,expectCostTime,expectSniNumber,expectHttpsPercent,expectNotHttps)
        delHeaderLen = len(expectRuleBody+"".join(expectRespondsuf))
        expectRespondHeadr = rcpBaseClass.rcp_header(respondMessType,expectRespondCode,deviceId,20+delHeaderLen//2,ruleId,messId=self.messId)
        expectRespondMessage = "".join(expectRespondHeadr)+expectRuleBody+"".join(expectRespondsuf)
        expectRespondMessage04 = rcpBaseClass.rcp_header(respondMessType,'04',deviceId,pktLen,ruleId,messId=self.messId)

        if str(expectRespondCode) !='04':
            return str(binascii.hexlify(requestMessage),encoding="utf-8"),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),ruleId
        else:
            return str(binascii.hexlify(requestMessage), encoding="utf-8"), ''.join(expectRespondMessage04).lower(), str(
                binascii.hexlify(respondRec), encoding="utf-8").lower(),ruleId

    def dropRule_L2(self,**kwargs):
        """
        :param messType: 2B
            0x0610  新增阻断请求(L2规则)
            0x0611  新增阻断应答(L2规则)
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
        print(kwargs)
        expectRespondCode = kwargs['expect_code']
        sipGroup = kwargs['sipg']
        dipGroup = kwargs['dipg']
        totalNum = kwargs['total']
        dayNum = kwargs['day']
        startTime = kwargs['starttime']
        endTime = kwargs['endtime']
        inGroup = kwargs['inGroup']
        vlanGroup = kwargs['vlang']
        mplsGroup = kwargs['mplsg']
        if str(kwargs['limit_type']).lower() == 'months' or kwargs['limit_type'] == 0:
            limitFlag = 0
        elif str(kwargs['limit_type']).lower() == 'days':
            limitFlag = 1
        elif str(kwargs['limit_type']).lower() == 'weeks':
            limitFlag = 2
        else:
            limitFlag = 10
        #serviceType = kwargs['serviceType']
        Pri = kwargs['pri']
        if str(kwargs['v4v6']).lower() == 'v4':
            ipFlag = 0
        elif str(kwargs['v4v6']).lower() == 'v6':
            ipFlag = 1
        else:
            ipFlag = 2
        deviceId = self.deviceId
        self.messId += 1
        requestMessType = '0610'
        respondMessType = '0611'
        rcpBaseClass = rcp_basic.RcpBasic()
        #rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(sipGroup,dipGroup,vlanGroup,GroupedPri,GaPri,GbPri,totalNum,dayNum,startTime,endTime,ipFlag=ipFlag)
        rcpBody = rcp_packet_data.RcpPacketData().addOrModifyRule(
            sipGroup,
            dipGroup,
            inGroup,
            vlanGroup,
            mplsGroup,
            limitFlag,
            Pri,
            totalNum,
            dayNum,
            self.cli_time_epoc_switchRcp(startTime,1),
            self.cli_time_epoc_switchRcp(endTime,1),
            ipFlag=ipFlag
        )
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
        print(str(binascii.hexlify(requestMessage),encoding="utf-8").lower())

        return str(binascii.hexlify(rcpBaseClass.data_format_change(rcpBody)),encoding="utf-8"),''.join(expectRespondMessage).lower(),str(binascii.hexlify(respondRec),encoding="utf-8").lower(),respondRuleIdDec

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

if __name__ == "__main__":
    a = RcpApi("192.168.128.235",deviceId=0,sslSwitch=0)
    # print(case1['src_v4'].split(','))


    #测试add增加 0=v4，1=v6，2=v4/v6

    #request,expectResult,result,ruleid = a.addRule("01",[['1.1.1.0/32',1001,1002,0,0]],[['2.2.2.0/32',2001,2002,0,0]],[[0,0]],1,1,1,0,0,0,0,0)  #129
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

for x in range(1, 4001):
    request, expectResult, result, ruleid = a.addRule_L2(
        expect_code=1,
        #sipg=[['12.0.0.1/24', x, x, "tcp", 255]],
        sipg=[['10.0.0.1/24', 0, 0, 0, 0]],
        dipg=[['2.2.2.2/24', 0, 0, 0, 0]],
        inGroup=[255],
        vlang=[],
        mplsg=[[x, x+1]],
        limit_type=0,
        pri=4,
        total=0,
        day=0,
        starttime=0,  # 开始时间（时间戳或特定格式）
        endtime=0,  # 结束时间（时间戳或特定格式）
        serviceType=0,  # 服务类型（根据实际需求填写，示例用0）
        v4v6='v4'
    )
    #print(request)
    #print(expectResult)
    #print(result)

    #request, expectResult, result, ruleid = a.delRule(1,"01")
    #request, expectResult, result, ruleid = a.delRule(2, "01")