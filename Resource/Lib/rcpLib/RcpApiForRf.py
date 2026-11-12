#!/bin/bash/env python
#-*- coding:utf-8 -*-
#Author PeiWenPing
#time:2024/5/7:13:47
#email:peiwenping@finslink.com

import configini
import RcpApiNew
import time
import ipaddress


class RcpApiForRf:

    def __init__(self):
        self.R3=RcpApiNew.RcpApi(configini.CLIENT['host_ip'], deviceId=configini.CLIENT['dev_id'], sslSwitch=configini.CLIENT['ssl_switch'])
    def _nullTozero(self,value):
        if value:
            value_new=[]
            for index,sip in enumerate(value):
                new_sip = []
                for index,va in enumerate(sip):
                    if not va :
                        va_zero = 0
                    elif index !=0 and  index !=3:
                        va_zero = int(va)
                    else:
                        va_zero = va
                    new_sip.append(va_zero)
                value_new.append(new_sip)
        else:
            value_new = value
        return value_new

    def _iniToRcp(self,**kwargs):
        kwargs['sipg'] = self._nullTozero(kwargs['sipg'])
        kwargs['dipg'] = self._nullTozero(kwargs['dipg'])

        return kwargs

    def _limitUnitConvert(self,**kwargs):
        """对单位进行转换"""
        a_B = ['total','day','expect_cost_total','expect_cost_day']
        a_b = ['expect_cost_total','expect_cost_day']
        times = {'default':1,"min":60,'hour':"60*60",'day':24*60*60}
        unit={'default':1,'K':1024,'M':1024*1024,"G":1024*1024*1024,"T":1024*1024*1024*1024}
        for title in a_B:
            if kwargs[title] == 0:
                pass
            else:
                unitS = str(kwargs[title]).upper()[-1] if str(kwargs[title]).upper()[-1] in unit.keys() else 'default'
                shu = str(kwargs[title]).upper()[:-1] if unitS != 'default' else str(kwargs[title]).upper()
                kwargs[title] = eval(shu) * unit[unitS]
        # for title in a_b:
        #     if kwargs[title] == 0:
        #         pass
        #     else:
        #         unitS = str(kwargs[title]).upper()[-1] if str(kwargs[title]).upper()[-1] in unit.keys() else 'default'
        #         shu = int(str(kwargs[title]).upper()[:-1]) if unitS != 'default' else int(str(kwargs[title]).upper())
        #         kwargs[title] = shu * unit[unitS]*8
        if kwargs['expect_cost_time'] == 0:
            pass
        else:
            unitS = str(kwargs['expect_cost_time']).upper()[-1] if  str(kwargs['expect_cost_time']).upper()[-1] in times.keys() else 'default'
            shu = str(kwargs['expect_cost_time']).upper()[:-1] if unitS !='default' else str(kwargs['expect_cost_time'])
            kwargs['expect_cost_time'] = eval(shu) * times[unitS]
        return kwargs

    def addSniRule(self,configFileName,title,ruleId=None):
        configR3 = configini.R3(configFileName).getSniRule(title)
        # var1 = self._iniToRcp(**configR3)
        var = configR3
        if 'modify' in var['operate'].lower():
            if ruleId is None:
                raise ValueError("modify 操作必须指定 ruleId")
            request, expectRespondMessage, actualrespond, ruleid = eval("self.R3.%s"%var['operate'])(ruleId,**var)
        else:
            request, expectRespondMessage, actualrespond, ruleid = eval("self.R3.%s" % var['operate'])(**var)
        return request,expectRespondMessage,actualrespond,ruleid

    def addOrModifyOrDrop(self,configFileName,title,ruleId=1):
        configR3 = configini.R3(configFileName).getR3(title)

        var1 = self._iniToRcp(**configR3)
        var = self._limitUnitConvert(**var1)
        if 'modify' in var['operate'].lower():
            request, expectRespondMessage, actualrespond, ruleid = eval("self.R3.%s" % var['operate'])(ruleId,**var)
        else:
            request, expectRespondMessage, actualrespond, ruleid = eval("self.R3.%s" % var['operate'])(**var)
        return request,expectRespondMessage,actualrespond,ruleid

    def addRuleDirect(self, **kwargs):
        var = self._iniToRcp(**kwargs)
        var = self._limitUnitConvert(**var)
        return self.R3.addRule(**var)

    def addRuleDirect_FiveTuple(self, **kwargs):
        var = self._iniToRcp(**kwargs)
        var = self._limitUnitConvert(**var)
        return self.R3.addRule_FiveTuple(**var)

    def alarmSet(self,configFileName,title):
        var = configini.R3(configFileName).getAlarm(title)
        # var = self._iniToRcp(**configR3)
        request, expectRespondMessage, actualrespond, ruleid = self.R3.alarmSet(**var)
        return request,expectRespondMessage,actualrespond,ruleid
        
    def alarmSet_fivetuple(self,configFileName,title):
        var = configini.R3(configFileName).getAlarm(title)
        # var = self._iniToRcp(**configR3)
        request, expectRespondMessage, actualrespond, ruleid = self.R3.alarmSet_FiveTuple(**var)
        return request,expectRespondMessage,actualrespond,ruleid

    def sniSet(self, configFileName, title,expectRespondCode='01'):
        var = configini.R3(configFileName).getSni(title)
        # var = self._iniToRcp(**configR3)
        var["expectRespondCode"] = expectRespondCode
        request, expectRespondMessage, actualrespond, ruleid = self.R3.sniSet(**var)
        return request, expectRespondMessage, actualrespond, ruleid

    def validMessType(self,configFileName,title):
        var = configini.R3(configFileName).getAlarm(title)
        # var = self._iniToRcp(**configR3)
        request, expectRespondMessage, actualrespond, ruleid = self.R3.validMessType(**var)
        return request,expectRespondMessage,actualrespond,ruleid

    def delete(self,ruleId,expectCode):
        request, expectRespondMessage, actualrespond, ruleid = self.R3.delRule(ruleId,expectCode,0)
        return request, expectRespondMessage, actualrespond, ruleid
        
    def delete_fivetuple(self,ruleId,expectCode):
        request, expectRespondMessage, actualrespond, ruleid = self.R3.delRule_FiveTuple(ruleId,expectCode,0)
        return request, expectRespondMessage, actualrespond, ruleid

    def delete_L2(self,ruleId,expectCode):
        request, expectRespondMessage, actualrespond, ruleid = self.R3.delRule_L2(ruleId,expectCode,0)
        return request, expectRespondMessage, actualrespond, ruleid

    def mirror(self,configFileName,title):
        var = configini.R3(configFileName).getMirror(title)
        request, expectRespondMessage, actualrespond, ruleid = self.R3.samplingMirr(**var)
        return request, expectRespondMessage, actualrespond, ruleid

    def queryNumber(self, configFileName, title):
        var = configini.R3(configFileName).getRuleNumber(title)
        request, expectRespondMessage, actualrespond, ruleid = self.R3.queryRuleNum(**var)
        return request, expectRespondMessage, actualrespond, ruleid
       
    def get_date_boundary_info(self, time_str):
        """
        返回时间字符串的边界重叠信息
        :param time_str: 设备时间字符串，格式 "YYYY.MM.DD-HH:MM:SS"
        :return: dict {'is_month_first': bool, 'is_monday': bool}
        """
        import datetime
        dt = datetime.datetime.strptime(str(time_str), "%Y.%m.%d-%H:%M:%S")
        return {'is_month_first': dt.day == 1, 'is_monday': dt.weekday() == 0}

    def get_next_time_boundary_rcp(self, current_time_str, boundary_type):
        """
        计算下一个时间边界（支持日/周/月），返回设备时间格式字符串
        :param current_time_str: 设备时间字符串，格式 "YYYY.MM.DD-HH:MM:SS"
        :param boundary_type: 'day'=明天0点, 'week'=下周一0点, 'month'=下月1号0点
        :return: 边界时间字符串，格式 "YYYY.MM.DD-HH:MM:SS"
        """
        import datetime
        dt = datetime.datetime.strptime(str(current_time_str), "%Y.%m.%d-%H:%M:%S")
        if boundary_type == 'day':
            target = (dt + datetime.timedelta(days=1)).replace(hour=0, minute=0, second=0)
        elif boundary_type == 'week':
            days_until_monday = (7 - dt.weekday()) % 7
            if days_until_monday == 0:
                days_until_monday = 7
            target = (dt + datetime.timedelta(days=days_until_monday)).replace(hour=0, minute=0, second=0)
        elif boundary_type == 'month':
            target = (dt.replace(day=1) + datetime.timedelta(days=32)).replace(day=1, hour=0, minute=0, second=0)
        else:
            raise ValueError("boundary_type must be 'day', 'week', or 'month', got: %s" % boundary_type)
        return target.strftime("%Y.%m.%d-%H:%M:%S")

    def cli_time_epoc_switchRcp(self,time1,format=0,interval_time=0):
        """
        设备时间和unix时间相互转换，并且增加上间隔时间
        :param time1: 要不unix，要不就是设备系统时间
        :param format:0:返回设备时间格式，1返回unix时间
        :param interval_time: 以秒为单位，在time1的基础上增加该时长
        :return:
        """
        return  self.R3.cli_time_epoc_switchRcp(time1,int(format),int(interval_time))

    def changeConfigOptionValue(self,configFileName,title,option,value=None):
        if value:
            configini.R3(configFileName).setR3(title, option, value)
        else:
            configini.R3(configFileName).setR3(title, option, value)

    def getConfigOptionValue(self, configFileName, title, option):
        "为了应对自动化一次性打流多个pcap文件，故而对title为多个进行处理，返回[value1,value2]"
        value = []
        for title1 in str(title).split(','):
            para = configini.confPacket(configFileName).getPacket(title1)
            value.append(para[option])
        return value

    def queryRuleNew(self,ruleId,configFileName,title):
        configR3 = configini.R3(configFileName).getR3(title)
        var1 = self._iniToRcp(**configR3)
        var = self._limitUnitConvert(**var1)
        # print(var)
        request, expectRespondMessage, actualrespond, ruleid = self.R3.queryRulenew(ruleId, **var)
        return request, expectRespondMessage, actualrespond, ruleid
        
    def queryRuleNew_fivetuple(self,ruleId,configFileName,title):
        configR3 = configini.R3(configFileName).getR3(title)
        var1 = self._iniToRcp(**configR3)
        var = self._limitUnitConvert(**var1)
        # print(var)
        request, expectRespondMessage, actualrespond, ruleid = self.R3.queryRulenew_FiveTuple(ruleId, **var)
        return request, expectRespondMessage, actualrespond, ruleid

    def queryRulenew_L2(self,ruleId,configFileName,title):
        configR3 = configini.R3(configFileName).getR3(title)
        var1 = self._iniToRcp(**configR3)
        var = self._limitUnitConvert(**var1)
        # print(var)
        request, expectRespondMessage, actualrespond, ruleid = self.R3.queryRulenew_L2(ruleId, **var)
        return request, expectRespondMessage, actualrespond, ruleid

    def queryRule(self,ruleid,expectRespondCode,expectRuleBody,expectCostTotal,expectCostDayTotal,expectCostTime,deviceId=0,expectSniNumber=0,expectHttpsPercent=0,expectNohttps=0):
        # print(var)
        request, expectRespondMessage, actualrespond, ruleid = self.R3.queryRule(ruleid,expectRespondCode,expectRuleBody,expectCostTotal,expectCostDayTotal,expectCostTime,expectSniNumber,expectHttpsPercent,expectNohttps,deviceId)
        return request, expectRespondMessage, actualrespond, ruleid

    def combine_request(self,request1,request2):
        """
        合并2个请求消息体
        :param request1:
        :param request2:
        :return:
        """
        list1 = [request1,request2]
        info = {}
        index = 0
        for request in list1:
            index += 1
            vlancount=int(request[32:40],16)
            vlancontext = request[40:48] if vlancount else ''
            v4v6 = int(request[40+8*vlancount:42+8*vlancount],16)
            ipcount = int(request[40 + 8 * vlancount + 8:40 + 8 * vlancount + 8 + 8], 16)
            if v4v6 ==0:
                v4context = request[40+8*vlancount+8+8:40+8*vlancount+8+8+ipcount*32] if ipcount else ''
                v6context=''
            if v4v6 ==1:
                v4context=''
                v6context = request[40 + 8 * vlancount + 8 + 8:40 + 8 * vlancount + 8 + 8 + ipcount * 80] if ipcount else ''
            if v4v6==2:
                v4context = request[40 + 8 * vlancount + 8 + 8:40 + 8 * vlancount + 8 + 8 + ipcount * 32] if ipcount else ''
                v6count = int(request[40 + 8 * vlancount + 8 + 8 + ipcount * 32:40 + 8 * vlancount + 8 + 8 + ipcount * 32+8])
                v6context = request[40 + 8 * vlancount + 8 + 8 + ipcount * 32+8:40 + 8 * vlancount + 8 + 8 + ipcount * 32+8+v6count*80] if v6count else ''
            info[index] = [vlancontext,v4context,v6context]

if __name__ == '__main__':


    a = RcpApiForRf()


    # 新增rcp规则命令行，遍历各种规则（后续增加自动化用例）2025.11.3
    #####组合****
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "v4_1")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "v4_2")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "v6_2")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "v6_3")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "v4_modify_1",1)
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "v6_modify_1",3)
    # request, expectRespondMessage, actualrespond, ruleid = a.queryRuleNew(1, 'rcprule_cli', "v4_modify")
    # request, expectRespondMessage, actualrespond, ruleid = a.queryRuleNew(2, 'rcprule_cli', "v6_modify")
    #a.delete(3, '01')
    #a.delete(2, '01')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "v4_block_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "v6_block_1")
    #####五元组****
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "add_v4_3")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "add_v4_2")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "add_v6_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "modify_readd_v4_1",106891)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "modify_readd_v6_1",55515)
    # request, expectRespondMessage, actualrespond, ruleid = a.queryRuleNew_fivetuple(106891, 'rcprule_cli', "modify_readd_v4_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.queryRuleNew_fivetuple(55515, 'rcprule_cli',"modify_readd_v6_1")
    # a.delete(49093, '01')
    # a.delete(49094, '01')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "block_v4_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "block_v6_1")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "block_v6_2")
    #####L2****
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "add_L2_v4_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "add_L2_v6_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "add_L2_v4_2")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "add_L2_v6_2")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "modify_v4_vlan_1",1001)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "modify_v6_vlan_1",1002)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "modify_v4_mpls_1",1003)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "modify_v6_mpls_1",1004)
    # request, expectRespondMessage, actualrespond, ruleid = a.queryRulenew_L2(1001, 'rcprule_cli', "modify_v4_vlan_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.queryRulenew_L2(1002, 'rcprule_cli', "modify_v6_vlan_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "block_L2_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "block_L2_2")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "test_2")

    # a.delete(1001, '01')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', "block_L2_2")

    ##告警阈值规则
    # request, expectRespondMessage, actualrespond, ruleid = a.alarmSet('rcprule_cli', 'alarm2')

    ##规则数量查询
    # request, expectRespondMessage, actualrespond, ruleid = a.queryNumber('rcprule_cli','ruleNumber1')


    #测试L2规则下发
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop( 'rule_priority', "add_L2_v4_1",1)
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', "add_L2_v4_2", 2)
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', "add_L2_v4_3", 2)
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_modify_limit', "rule_add_vlan_1_200")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpL2', "add_L2_5")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpL2', "modify_L2_6", 1)
    request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('ingroup', "add_L2_v6")

    ##测试L2规则删除
    #request, expectRespondMessage, actualrespond, ruleid =a.delete_L2(65538,"01")
    #request, expectRespondMessage, actualrespond, ruleid = a.delete_L2(1, "01")

    #测试L2修改
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', "modify_L2_v4_1", 65536)


    #测试L2阻断
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', "add_block_L2_v6_1", 2)

    #测试L2规则查询

    #request, expectRespondMessage, actualrespond, ruleid = a.queryRulenew_L2(1,'rcpL2', "add_L2_5")

    #request, expectRespondMessage, actualrespond, ruleid = a.queryRulenew_L2(1001, 'rcpL2', "add_L2_1")
    #测试IP组规则下发
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_modify_rule', "rule_add", 1)
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_modify_rule', "v6_del_new", 1)
    #request, expectRespondMessage, actualrespond, ruleid = a.queryRuleNew(1,'rule_priority', "IPgroup")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', "IPgroup_block", 2)
    #a.delete_fivetuple(89628,"01")
    #a.delete(2,"01")
    #a.delete_L2(65536, '01')
    #a.delete_fivetuple(89628, '01')

    #request, expectRespondMessage, actualrespond, ruleid = a.delete_L2(65536, "01")
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpL2', 'add_five_tuple_v4_1_1')
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpL2', 'add_L2_v4_1',65555)
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpL2', "block_L2_1", 2)
    #request, expectRespondMessage, actualrespond, ruleid = a.queryRulenew_L2( 65536,'rcpL2', "add_L2_v4_1")
    #request, expectRespondMessage, actualrespond, ruleid = a.queryRulenew_L2(89628,'rcpL2', 'add_five_tuple_v4_1_1')
    #
    #print(request)
    #print(expectRespondMessage)
    #print(f"设备响应：{actualrespond}")
    #

    #下发L2规则
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_modify_limit', 'rule_add_vlan_1_200')
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpClearLimit', 'v4_day_fivetuple')   
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpClearLimit', 'v4_week_fivetuple',2)
    #
    # #下发五元组规则
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpFiveTuple_New', 'add_v4_4', 1)
    #request, expectRespondMessage, actualrespond, ruleid = a.queryRulenew_FiveTuple(1,'rcpFiveTuple_New', 'add_v4_4')
    #
    # #下发组合规则
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcprule_cli', 'v4_1', 1)


    # 测试业务优先级
    # 点对点业务
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', "vlan_fd_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', "vlan_fd_2")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', "vlan_fd_3")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', "vlan_block_1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', "vlan_block_2")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', "vlan_block_3")
    #
    # # #PRI2,dx阻断
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', "PRI2-dx-block-1")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', 'PRI2-dx-block-2')
    # #
    # # #PRI4,电商业务放行
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', 'PRI4-bussiness-fd-1')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', 'PRI4-bussiness-fd-2')
    # #
    # # #PRI6,境内运维ip放行
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', 'PRI6-JNOps-fd-1')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new', 'PRI6-JNOps-fd-2')
    #
    # # #PRI8,境内1w网段阻断（组合）
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new','PRI8-JN1w-block')
    #
    # # #PRI10,境内服务器ip放行
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new','PRI10-JNserver-fd-1')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new','PRI10-JNserver-fd-2')
    #
    # # #PRI12,境内ip阻断
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new','PRI12-JN-block-1')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new','PRI12-JN-block-2')
    #
    # # #PRI14,境外服务器ip放行
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new','PRI14-JWserver-fd-1')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority _new','PRI14-JWserver-fd-2')

    #/////////////////////////////////////////////////////////////////////////////////////////
    #测试规则优先级
    #最高优先级放行
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'PRI0-bussiness-fd-1')
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'PRI0-bussiness-fd-2')
    #
    # # #维护优先级2
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'PRI2-bussiness-fd-1')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'PRI2-bussiness-fd-2')
    # #
    # # ##国内源目的ip阻断
    # # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'PRI4-bussiness-BLOCK')
    # #
    # # ##测试境内ip放行6
    # # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'PRI6-bussiness-fd-1')
    #
    # ##调整优先级4和优先级6###
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority','PRI4-bussiness-BLOCK-1-new')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority','PRI4-bussiness-BLOCK-2-new')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority','PRI4-bussiness-fd-1-new')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority','PRI4-bussiness-fd-2-new')
    # #
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'PRI6-bussiness-BLOCK-new')
    #
    # ##优先级8 单向10w阻断
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority','PRI8-bussiness-BLOCK-1-new')
    #
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority','PRI8-bussiness-BLOCK-2-new')
    #
    # ##优先级10，境外放行
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority',
    #                                                                            'PRI10-bussiness-fd-1')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority',
    #                                                                            'PRI10-bussiness-fd-2')
    #
    print("请求" + str(request))
    print("应答" + str(actualrespond))


    #a.delete(7, '01')

    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_modify_rule','rule_add')
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_modify_rule', 'v6_del',ruleId=1)
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add', 'test')
    # print(request)
    # print(expectRespondMessage == actualrespond)
    #测试规则优先级
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'A2-A1-FD-1')
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'A2-A1-FD-2')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'A2-A3-BLOCK-1')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'A2-A3-BLOCK-2')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'A2-any-FD-1')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority', 'A2-any-FD-2')

    # a.delete(1, '01')
    # a.delete(2, '01')
    # a.delete(3, '01')
    # a.delete(4, '01')
    #request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_priority','test')
    # print(request)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add', 'v4_add', ruleId=1)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add', 'v6_add', ruleId=1)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add', 'v4v6_add', ruleId=1)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add', 'add_mult', ruleId=1)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add', 'add_total',ruleId=1)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add', 'add_total_1',ruleId=1)
    # request, expectRespondMessage, actualrespond, ruleid = a.addSniRule('interface_sni_acl', 'add_sniacl_hash_63_1', ruleId=1)
    # request, expectRespondMessage, actualrespond, ruleid = a.addSniRule('interface_sni_acl', 'add_sniacl_hash_63_2', ruleId=1)
    #
    # print(expectRespondMessage == actualrespond)
    # a.sniSet("sni",'3')
    # request, expectRespondMessage, actualrespond, ruleid = a.addSniRule("interface_sni_acl","test")
    # print(expectRespondMessage)
    # print(actualrespond)
    #a.changeConfigOptionValue("config","client","dst_ip","192.168.11.111")

    # a.queryRuleNew(1,"interface_add_sni","v4_add_sni")

    # request, expectRespondMessage, actualrespond, ruleid = a.queryRule(1,"01","01070101000000000000000100000010",0,0,0,0,0,0,0,)
    # print(actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.sniSet('sni','2')
    # print(actualrespond)
    # print(expectRespondMessage)
    # print(expectRespondMessage == actualrespond)
    # a.changeConfigOptionValue("interface_add_sni","v4_add_sni","servcieType",2)
    # #
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add_sni','v4_add_sni',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)


    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_2_1_0',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_3_2_0',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_4_0_1',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_5_0_0',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_6_0_2',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_7_7_6',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_8_3_0',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_9_0_3',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_10_4_0',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_11_0_4',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_12_5_0',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','grouped_13_0_6',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','fuyong',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)



    # b = a.cli_time_epoc_switchRcp("28149",0)
    # print(b)
    # a.delete(1,'01')
    # a.delete(2, '01')
    # time.sleep(30)
    # a.delete(1,'01')

    #code
    #valid messType
    # a.validMessType("bj_test","alarm")
    #rule no exist
    # a.delete(170) #del
    # a.queryRuleNew(170,'bj_test','v4add') #query
    # a.addOrModifyOrDrop( 'bj_test', 'modify-del-v4-v6',170)  # modify-del
    # a.addOrModifyOrDrop( 'bj_test', 'modify-add-v4-v6',170)  # modify-add
    # a.addOrModifyOrDrop('bj_test', 'modify-readd-v4-v6',170)  # modify-readd
    #rule is exist
    # a.changeConfigOptionValue('bj_test', 'v4add', "total", "50m")
    # a.changeConfigOptionValue('bj_test', 'v4add', "day", "50m")
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('xianchang','fuyong',ruleId=1)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)
#     # a.changeConfigOptionValue('bj_test', 'v4add', "total", "70m")
#     # a.changeConfigOptionValue('bj_test', 'v4add', "day", "70m")
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v4add')
#
#     # a.changeConfigOptionValue('bj_test', 'v6add', "total", "50m")
#     # a.changeConfigOptionValue('bj_test', 'v6add', "day", "50m")
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v6add')
#     # a.changeConfigOptionValue('bj_test', 'v6add', "total", "70m")
#     # a.changeConfigOptionValue('bj_test', 'v6add', "day", "70m")
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v6add')
#
#     # a.changeConfigOptionValue('bj_test', 'v4v6add', "total", "50m")
#     # a.changeConfigOptionValue('bj_test', 'v4v6add', "day", "50m")
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v4v6add')
#     # a.changeConfigOptionValue('bj_test', 'v4v6add', "total", "70m")
#     # a.changeConfigOptionValue('bj_test', 'v4v6add', "day", "70m")
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v4v6add')
#
#     #rule full
#     # for i in range(16130):
#     #     print("下发第%s条" % i)
#     #     sip = ipaddress.IPv4Address(ipaddress.ip_address('192.10.1.1')+i)
#     #     dip =ipaddress.IPv4Address(ipaddress.ip_address('10.10.1.1')+i)
#     #     a.changeConfigOptionValue('bj_test', 'rule16129', "sipg", "%s/32,0,0,0,0"%(sip))
#     #     a.changeConfigOptionValue('bj_test', 'rule16129', "dipg", "%s/32,0,0,0,0"%(dip))
#     #     request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','rule16129')
#     #     print(expectRespondMessage == actualrespond)
#
    # a.delete(16130,'01')
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add','add_total_dingwei')
    # print(ruleid)
    # print(request)
    # print(expectRespondMessage == actualrespond)
    # # time.sleep(60)
    # request, expectRespondMessage, actualrespond, ruleid = a.queryRule(16130,'01',"010101",0,0,0)
    # print(request)
    # print(expectRespondMessage)
    # print(actualrespond)
    # print(expectRespondMessage == actualrespond)

    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add','add_total_dingwei11',ruleId=ruleid)
    # print(ruleid)
    # print(request)
    # print(expectRespondMessage == actualrespond)
    # time.sleep(100)
    #
    # a = RcpApiForRf()
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_add','add_total_dingwei_del',ruleId=16130)
    # print(request)
    # print(expectRespondMessage == actualrespond)

    # request, expectRespondMessage, actualrespond, ruleid = a.delete(16130,'01')
    # print(request)
    # print(expectRespondMessage == actualrespond)

#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v6add')
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v4v6add')
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-add-v6',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v4add',ruleId=129)
    # print(request)
    # print(expectRespondMessage == actualrespond)
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-add-v4-v6',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-del-v6',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-del-v4',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-del-v4-v6',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-readd-v4',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-readd-v6',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-readd-v4-v6',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.delete(ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#     # #查询v4: tcpreplay -l 172 -i enp3s0f0 v4add.pcap
#     # a.delete(129)
#     #
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v4add')
#     # # print(request)
#     # # print(expectRespondMessage == actualrespond)
#     # time.sleep(10)
#     # a.changeConfigOptionValue('bj_test','v4add',"request",request)
#     # a.changeConfigOptionValue('bj_test', 'v4add', "expect_cost_total", "50m")
#     # a.changeConfigOptionValue('bj_test', 'v4add', "expect_cost_day", "50m")
#     # a.changeConfigOptionValue('bj_test', 'v4add', "expect_cost_time", 11)
#     # request, expectRespondMessage, actualrespond, ruleid = a.queryRule(ruleid,'bj_test','v4add')
#     # print(expectRespondMessage)
#     # print(actualrespond)
#     # print(expectRespondMessage == actualrespond)
# # 查询v6: tcpreplay -l 172 -i enp3s0f0 v6add.pcap
# #     a.delete(129)
# #
# #     starttime = a.cli_time_epoc_switchRcp('2024.05.16-11:11:02',1,)
# #     endtime = a.cli_time_epoc_switchRcp('2024.05.17-23:11:02',1)
# #     a.changeConfigOptionValue('bj_test', 'v6add', "starttime", starttime)
# #     a.changeConfigOptionValue('bj_test', 'v6add', "endtime", endtime)
# #     a.changeConfigOptionValue('bj_test', 'v6add', "total",'90m' )
# #     a.changeConfigOptionValue('bj_test', 'v6add', "day", '10m')
# #


#     # a.changeConfigOptionValue('bj_test', 'modify-add-v4-v6', "total",'80m' )
#     # a.changeConfigOptionValue('bj_test', 'modify-add-v4-v6', "day", "20m")
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-add-v4-v6',ruleId=129)
#
#     # a.changeConfigOptionValue('bj_test', 'modify-del-v4-v6', "total",'80m' )
#     # a.changeConfigOptionValue('bj_test', 'modify-del-v4-v6', "day", "40m")
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','modify-del-v4-v6',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#
#     # print("请打流")
#     # time.sleep(30)
#     # # a.changeConfigOptionValue('bj_test','v6add',"request",request)
#     # a.changeConfigOptionValue('bj_test', 'v6add', "expect_cost_total", "10m")
#     # a.changeConfigOptionValue('bj_test', 'v6add', "expect_cost_day", "10m")
#     # a.changeConfigOptionValue('bj_test', 'v6add', "expect_cost_time", 31)
#     # request, expectRespondMessage, actualrespond, ruleid = a.queryRuleNew(129,'bj_test','v6add')
#     # print(expectRespondMessage)
#     # print(actualrespond)
#     # print(expectRespondMessage == actualrespond)
#
#
#     # ##drop
#     #
#     #v4drop
#     # starttime = a.cli_time_epoc_switchRcp('2024.05.16-11:11:02',1,60)
#     # endtime = a.cli_time_epoc_switchRcp('2024.05.16-23:11:02',1)
#     # a.changeConfigOptionValue('bj_test', 'v6add', "starttime", starttime)
#     # a.changeConfigOptionValue('bj_test', 'v6add', "endtime", endtime)
#     # a.changeConfigOptionValue('bj_test', 'v4drop', "total",'90m' )
#     # a.changeConfigOptionValue('bj_test', 'v4drop', "day", '10m')
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v4drop',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#     # a.changeConfigOptionValue('bj_test','v4drop',"request",request)
#
#     # print("请打流")
#     # time.sleep(30)
#     # # a.changeConfigOptionValue('bj_test','v6add',"request",request)
#     # a.changeConfigOptionValue('bj_test', 'v4drop', "expect_cost_total", "10m")
#     # a.changeConfigOptionValue('bj_test', 'v4drop', "expect_cost_day", "10m")
#     # a.changeConfigOptionValue('bj_test', 'v4drop', "expect_cost_time", 31)
#     # request, expectRespondMessage, actualrespond, ruleid = a.queryRule(129,'bj_test','v4drop')
#     # print(expectRespondMessage)
#     # print(actualrespond)
#     # print(expectRespondMessage == actualrespond)
#
# #v6drop
#     # starttime = a.cli_time_epoc_switchRcp('2024.05.16-11:11:02',1,60)
#     # endtime = a.cli_time_epoc_switchRcp('2024.05.16-23:11:02',1)
#     # a.changeConfigOptionValue('bj_test', 'v6drop', "starttime", )
#     # a.changeConfigOptionValue('bj_test', 'v6drop', "endtime", )
#     # a.changeConfigOptionValue('bj_test', 'v6drop', "total", )
#     # a.changeConfigOptionValue('bj_test', 'v6drop', "day", )
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v6drop',ruleId=129)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#     # a.changeConfigOptionValue('bj_test','v4drop',"request",request)
#     #
#     # print("请打流")
#     # time.sleep(30)
#     # a.changeConfigOptionValue('bj_test','v6drop',"request",request)
#     # a.changeConfigOptionValue('bj_test', 'v6drop', "expect_cost_total", "10m")
#     # a.changeConfigOptionValue('bj_test', 'v6drop', "expect_cost_day", "10m")
#     # a.changeConfigOptionValue('bj_test', 'v6drop', "expect_cost_time", 31)
#     # request, expectRespondMessage, actualrespond, ruleid = a.queryRule(129,'bj_test','v6drop')
#     # print(expectRespondMessage)
#     # print(actualrespond)
#     # print(expectRespondMessage == actualrespond)
#
# # v4v6drop
# #     starttime = a.cli_time_epoc_switchRcp('2024.05.16-11:11:02',1,60)
# #     endtime = a.cli_time_epoc_switchRcp('2024.05.16-23:11:02',1)
# #     a.changeConfigOptionValue('bj_test', 'v4v6drop', "starttime", )
# #     a.changeConfigOptionValue('bj_test', 'v4v6drop', "endtime", )
# #     a.changeConfigOptionValue('bj_test', 'v4v6drop', "total", )
# #     a.changeConfigOptionValue('bj_test', 'v4v6drop', "day", )
#     request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('bj_test','v4v6drop',ruleId=129)
#     print(request)
# #     print(expectRespondMessage == actualrespond)
# #
# #     print("请打流")
# #     time.sleep(30)
# #     a.changeConfigOptionValue('bj_test','v4v6drop',"request",request)
# #     a.changeConfigOptionValue('bj_test', 'v4v6drop', "expect_cost_total", "10m")
# #     a.changeConfigOptionValue('bj_test', 'v4v6drop', "expect_cost_day", "10m")
# #     a.changeConfigOptionValue('bj_test', 'v4v6drop', "expect_cost_time", 31)
# #     request, expectRespondMessage, actualrespond, ruleid = a.queryRule(129,'bj_test','v4v6drop')
# #     print(expectRespondMessage)
# #     print(actualrespond)
# #     print(expectRespondMessage == actualrespond)
#
# #镜像
#     # request, expectRespondMessage, actualrespond, ruleid = a.mirror('bj_test','mirror')
#     # print(expectRespondMessage == actualrespond)
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.mirror('bj_test','mirror_close')
#     # print(expectRespondMessage == actualrespond)
#
#
# #alarm
#     # request, expectRespondMessage, actualrespond, ruleid = a.alarmSet('bj_test','alarm')
#     # print(expectRespondMessage==actualrespond)
#     #
#     # request, expectRespondMessage, actualrespond, ruleid = a.alarmSet('bj_test','alarmzero')
#     # print(expectRespondMessage==actualrespond)
#
# ##规则数量查询
#     # forward 10条
#     # for i in range(1,11):
#     #     request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_number','forwar%s'%i)
#     #     print(expectRespondMessage==actualrespond)
#
#     # drop 20条
#     # for i in range(1,21):
#     #     request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_number','drop%s'%i)
#     #     print(expectRespondMessage==actualrespond)
#
#     # alarm设置
#     # request, expectRespondMessage, actualrespond, ruleid = a.alarmSet('bj_test','alarm')
#     # print(expectRespondMessage==actualrespond)
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.alarmSet('bj_test','alarmzero')
#     # print(expectRespondMessage==actualrespond)
#     #
#     # request, expectRespondMessage, actualrespond, ruleid = a.alarmSet('bj_test','alarmout')
#     # print(expectRespondMessage==actualrespond)
#
#
#     #mirror设置
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('time','forwardRcp_5')
#     # print(expectRespondMessage == actualrespond)
#
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.mirror('bj_test','mirror_close')
#     # print(expectRespondMessage == actualrespond)
#
#     # v6limit
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_number', "v6limit")
#     # print(expectRespondMessage==actualrespond)
#
#     #v4limit
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rule_number', "v4limit")
#     # print(expectRespondMessage==actualrespond)
#
#
#     #查询规则数量
#     # request, expectRespondMessage, actualrespond, ruleid = a.queryNumber('rule_number','ruleNumber1')
#     # print(expectRespondMessage)
#     # print(actualrespond)
#     # print(expectRespondMessage == actualrespond)
#
#
#
#     # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('interface_modify_limit','modify_limit',ruleId=1)
#     # print(request)
#     # print(expectRespondMessage == actualrespond)
#     a.addOrModifyOrDrop("interface_modify_limit","modify_v6_add",1)
#     a.addOrModifyOrDrop("interface_modify_limit","modify_v4_del",1)
#     # c = a.getConfigOptionValue("netflow_packet","netflow_v4_flwcnt_20","sip",)
#     #     # print(c)
    #五元组添加
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpFiveTuple','add_v4_1')
    # print(request)
    # print(expectRespondMessage == actualrespond)
    # a = RcpApiForRf()
    # request, expectRespondMessage, actualrespond, ruleid = a.addOrModifyOrDrop('rcpFiveTuple','add_v4_1')
    # print(request)
    # print(expectRespondMessage == actualrespond)