#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2022/3/7:13:32
# email:peiwenping@finslink.com
import binascii
import re
import ipaddress

import rcp_basic
pro_to_id = rcp_basic.pro_to_id


class RcpPacketData(rcp_basic.RcpBasic):
    """
    RCP相关消息块报文构建函数
    """

    # def addOrModifyRule(self,pro=("tcp",255),sipGroup=[["192.168.1.1/24",1,2]],dipGroup=[["192.168.1.1/24",1,2]],totalNum=0,dayNum=0,startTime=0,endTime=0,changeFlag=3):
    #     """
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
    #
    #     #计算消息体的长度
    #     sipIpadd = sipGroup[0][0].split('/')[0]
    #     dipIpadd = dipGroup[0][0].split('/')[0]
    #     ipType = '00' if '.' in sipIpadd or  '.' in dipIpadd  else '01'
    #     v46Flag = 'V4' if '.' in sipIpadd or  '.' in dipIpadd  else 'V6'
    #     sipLen = len(sipGroup)
    #     dipLen = len(dipGroup)
    #     rcp_mess_block = []
    #     rcp_mess_block.append(ipType) #v4/v6标识
    #     rcp_mess_block.append(self.dec_to_hex(pro_to_id[str(pro[0]).upper()])) #协议字段
    #     rcp_mess_block.append(self.dec_to_hex(pro[1]))  # 协议掩码
    #     rcp_mess_block.append(self.dec_to_hex(changeFlag)) #变更字段
    #     sipLenC = 0 if '0/0' in sipGroup[0][0] and int(sipGroup[0][2]) ==0 else sipLen
    #     # sipLenC = 0 if (sipLen == 1 and len(sipGroup[0][0].split('/')[0].split('.')) == 1) or (sipLen == 1 and len(sipGroup[0][0].split('/')[0].split(':')) == 1) else sipLen
    #     rcp_mess_block += self.mult_bytes_to_one_byte(4, sipLenC)  # 原条目数
    #     for i in range(sipLen): #处理源SIP组
    #         if 'V4' == str(v46Flag).upper():
    #             sipAndMask = sipGroup[i][0].split('/')
    #             sipValue = sipAndMask[0].split('.') if len(sipAndMask[0].split('.')) != 1 else [0,0,0,0]
    #             sipMaskLen = sipAndMask[1]
    #             spStart = sipGroup[i][1]
    #             spEnd = sipGroup[i][2]
    #             sipValueList = [self.dec_to_hex(i) for i in sipValue]
    #             # if sipLen == 1 and len(sipAndMask[0].split('.')) == 1:
    #             if not sipLenC:
    #                 pass
    #             else:
    #                 rcp_mess_block += sipValueList #源IP地址
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2,sipMaskLen) #源IP掩码长度
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, '00') #掩码长度后面2个预留字节
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, spStart)  # 源起始端口
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, spEnd)  # 源结束端口
    #         else:
    #             sipAndMask = sipGroup[i][0].split('/')
    #             sipValue = self.v6JianToQuan(sipAndMask[0]) if len(self.v6JianToQuan(sipAndMask[0])) !=1 else '0:0:0:0:0:0:0:0'
    #             sipMaskLen = sipAndMask[1]
    #             spStart = sipGroup[i][1]
    #             spEnd = sipGroup[i][2]
    #             # sipValueList = [ i for i in sipValue.split(":")]
    #             sipValueList = []
    #             for i in sipValue.split(':'):
    #                 sipValueList += self.mult_bytes_to_one_byte(2,i,True)
    #             # if sipLen == 1 and len(self.v6JianToQuan(sipAndMask[0])) == 1 and int(sipGroup[0][2]) ==0:
    #             if not sipLenC:
    #                 pass
    #             else:
    #
    #                 rcp_mess_block += sipValueList  # 源IP地址
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, sipMaskLen)  # 源IP掩码长度
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, '00')  # 掩码长度后面2个预留字节
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, spStart)  # 源起始端口
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, spEnd)  # 源结束端口
    #
    #     # dipLenC = 0 if dipLen==1 and len( dipGroup[0][0].split('/')[0].split('.')) == 1  else dipLen
    #     dipLenC = 0 if '0/0' in dipGroup[0][0] and int(dipGroup[0][2]) ==0  and int(dipGroup[0][2]) ==0 else dipLen
    #     rcp_mess_block += self.mult_bytes_to_one_byte(4, dipLenC)  # 原条目数
    #     for i in range(dipLen):  # 处理目的SIP组
    #         if 'V4' == str(v46Flag).upper():
    #             dipAndMask = dipGroup[i][0].split('/')
    #             dipValue = dipAndMask[0].split('.') if len(dipAndMask[0].split('.')) != 1 else [0,0,0,0]
    #             dipMaskLen = dipAndMask[1]
    #             dpStart = dipGroup[i][1]
    #             dpEnd = dipGroup[i][2]
    #             dipValueList = [self.dec_to_hex(i) for i in dipValue]
    #             # if dipLen==1 and len(dipAndMask[0].split('.')) == 1:
    #             if not dipLenC:
    #                 pass
    #             else:
    #                 rcp_mess_block += dipValueList  # 源IP地址
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, dipMaskLen)  # 源IP掩码长度
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, '00')  # 掩码长度后面2个预留字节
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, dpStart)  # 源起始端口
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, dpEnd)  # 源结束端口
    #         else:
    #             dipAndMask = dipGroup[i][0].split('/')
    #             dipValue = self.v6JianToQuan(dipAndMask[0]) if len(self.v6JianToQuan(dipAndMask[0])) !=1 else '0:0:0:0:0:0:0:0'
    #             dipMaskLen = dipAndMask[1]
    #             dpStart = dipGroup[i][1]
    #             dpEnd = dipGroup[i][2]
    #             dipValueList = []
    #             for i in dipValue.split(':'):
    #                 dipValueList += self.mult_bytes_to_one_byte(2,i,True)
    #             # if dipLen == 1 and len(self.v6JianToQuan(dipAndMask[0])) == 1 and int(dipGroup[0][2]) ==0:
    #             if not dipLenC:
    #                pass
    #             else:
    #                 rcp_mess_block += dipValueList  # 源IP地址
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, dipMaskLen)  # 源IP掩码长度
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, '00')  # 掩码长度后面2个预留字节
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, dpStart)  # 源起始端口
    #                 rcp_mess_block += self.mult_bytes_to_one_byte(2, dpEnd)  # 源结束端口
    #     rcp_mess_block += self.mult_bytes_to_one_byte(8,totalNum)
    #     rcp_mess_block += self.mult_bytes_to_one_byte(8, dayNum)
    #     rcp_mess_block += self.mult_bytes_to_one_byte(8, startTime)
    #     rcp_mess_block += self.mult_bytes_to_one_byte(8, endTime)
    #     return rcp_mess_block
    def addOrModifyRule(
            self,
            sipGroup=[["192.168.1.1/24",1,2,"tcp",255]],
            dipGroup=[["192.168.1.1/24",1,2,"tcp",255]],
            inGroup=255,
            vlanGroup=[[1,2]],
            mplsGroup=[[3,4]],
            limitFlag=0,
            Pri=0,
            totalNum=0,
            dayNum=0,
            startTime=0,
            endTime=0,
            changeFlag=0,
            ipFlag=1
    ):
        """
        :param changeFlag: 1B,0:Ip组内新增源目的三元组;1:表示删减;2:重新下发
        :param sip:[v4:4B,v4Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,sportSt:2B,sportEnd:2B,pro:1B,proMask:1B]
        :param dip:[v4:4B,v4Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]、[v6:16B,v6Mask:2B,dportSt:2B,dportEnd:2B,pro:1B,proMask:1B]
        :param totalNum:8B,0:不限量
        :param dayNum:8B,0:不限量
        :param startTime:8B
        :param endTime:8B
        :param ipFlag 0:V4,1:v6,2:v4/v6
        :return:
        """
        rcp_mess_block = []

        #调整ingroup位置
        rcp_mess_block += self.mult_bytes_to_one_byte(2, inGroup)
        #print(f"添加ingroup后消息体{rcp_mess_block}")
        #增加vlan条目数-20240625
        #调整vlan个数长度为2个字节
        if not len(vlanGroup):
            rcp_mess_block += self.mult_bytes_to_one_byte(2,"00")
        else:
            rcp_mess_block += self.mult_bytes_to_one_byte(2, len(vlanGroup))
            for vlan_index in vlanGroup:
                #print(vlan_index)
                rcp_mess_block+=self.mult_bytes_to_one_byte(2,vlan_index[0])
                rcp_mess_block+=self.mult_bytes_to_one_byte(2,vlan_index[1])
        print(f"增加vlan标签后消息体{rcp_mess_block}")

        #修改mpls两层
        #print(f"mpls标签组{mplsGroup}")
        if not len(mplsGroup):
            rcp_mess_block += self.mult_bytes_to_one_byte(4,"00")
        else:
            rcp_mess_block += self.mult_bytes_to_one_byte(4, len(mplsGroup))

            for mpls_index in mplsGroup:
                print(type(mpls_index[0]))
                print(mpls_index[1])
                if int(mpls_index[0]) == 4294967295 :
                    print("ok")
                    rcp_mess_block += self.mult_bytes_to_one_byte(4, 4294967295)
                else:
                    rcp_mess_block+=self.mult_bytes_to_one_byte(4,int(mpls_index[0])<<12)
                if int(mpls_index[1]) == 4294967295 :
                    print("ok")
                    rcp_mess_block += self.mult_bytes_to_one_byte(4, 4294967295)
                else:
                    rcp_mess_block+=self.mult_bytes_to_one_byte(4, int(mpls_index[1])<<12)

        #增加mpls标签（一层）
        #print(f"mpls标签组{mplsGroup}")
        #if not len(mplsGroup):
            #rcp_mess_block += self.mult_bytes_to_one_byte(4,"00")
        #else:
            #rcp_mess_block += self.mult_bytes_to_one_byte(4, len(mplsGroup))

            #for mpls_index in mplsGroup:
               #rcp_mess_block+=self.mult_bytes_to_one_byte(4,int(mpls_index)<<12)
        print(f"增加mpls标签后消息体{rcp_mess_block}")

        rcp_mess_block.append(str(ipFlag)) #v4/v6标识
        print(f"增加v4/v6标识后消息体{rcp_mess_block}")

        print(f"限量周期值为{limitFlag}")
        rcp_mess_block.append(self.dec_to_hex(limitFlag))  # 限量周期标识
        print(f"增加限量周期标识后消息体{rcp_mess_block}")


        #rcp_mess_block.append(self.dec_to_hex(changeFlag))   #原先为限量周期字段，后修改为变更字段

        #print(f"增加限量/变更后消息体{rcp_mess_block}")

        rcp_mess_block.append(self.dec_to_hex(Pri))  # 1byte
        #rcp_mess_block.append(self.dec_to_hex(0))
        #GaGb_pri =self.dec_to_hex(GaPri)[1:]+self.dec_to_hex(GbPri)[1:]   #4bit+4bit)
        #rcp_mess_block.append(self.dec_to_hex(Pri))  #1byte

        print(f"增加优先级后消息体{rcp_mess_block}")

        #rcp_mess_block += self.mult_bytes_to_one_byte(2, '00')  # 原先的协议和协议掩码字段，现改成默认0

        #rcp_mess_block.append(self.dec_to_hex(0))

        #print(f"增加填充后/五元组前后消息体{rcp_mess_block}")
         #rcp_mess_block.append(GaGb_pri)  #1byte

        rcp_mess_block.append(self.dec_to_hex(changeFlag)) #变更字段

        print(f"增加变更标识后消息体{rcp_mess_block}")
        #对sip和dip组进行处理
        validSipv4 = [i for i in sipGroup if  '.' in i[0]]
        validSipv6 = [i for i in sipGroup if  ':' in i[0]]
        validDipv4 = [i for i in dipGroup if '.' in i[0]]
        validDipv6 = [i for i in dipGroup if  ':' in i[0]]
        #===IPGroup
        valueOrder = [validSipv4,validSipv6,validDipv4,validDipv6] if ipFlag != 2 else [validSipv4,validDipv4,validSipv6,validDipv6]
        # for index,ipvalue in {1:validSipv4,2:validSipv6,3:validDipv4,4:validDipv6}.items():
        for index, ipvalue in enumerate(valueOrder,start=1):
            if int(ipFlag) == 2 :rcp_mess_block += self.mult_bytes_to_one_byte(4, len(ipvalue))
            if ipvalue:
                if int(ipFlag) != 2:rcp_mess_block += self.mult_bytes_to_one_byte(4, len(ipvalue))
                for sip in ipvalue:
                    sipAndMask = sip[0].split('/')
                    sipValue = sipAndMask[0] if '.' in sipAndMask[0] else self.v6JianToQuan(sipAndMask[0])
                    sipmasklen = sipAndMask[1]
                    rcp_mess_block = rcp_mess_block + [self.dec_to_hex(i) for i in sipValue.split('.')] if '.' in sipValue else rcp_mess_block + [j for i in sipValue.split(':') for j in self.mult_bytes_to_one_byte(2,i,True)] #IP value
                    rcp_mess_block += self.mult_bytes_to_one_byte(2, sipmasklen)  # IP掩码长度
                    rcp_mess_block.append(self.dec_to_hex(pro_to_id[str(sip[3]).upper()]))  # 协议字段
                    rcp_mess_block.append(self.dec_to_hex(sip[4]))  # 协议掩码
                    rcp_mess_block += self.mult_bytes_to_one_byte(2, sip[1])  # 起始端口
                    rcp_mess_block += self.mult_bytes_to_one_byte(2, sip[2])  # 结束端口
            else:
                if int(ipFlag) == 0 and index ==1 and not validSipv4 :rcp_mess_block += self.mult_bytes_to_one_byte(4, len(ipvalue))
                if int(ipFlag) == 0 and index == 3 and not validDipv4: rcp_mess_block += self.mult_bytes_to_one_byte(4,len(ipvalue))
                if int(ipFlag) ==1  and index == 2 and not validSipv6 :rcp_mess_block += self.mult_bytes_to_one_byte(4, len(ipvalue))
                if int(ipFlag) == 1 and index == 4 and not validDipv6: rcp_mess_block += self.mult_bytes_to_one_byte(4,len(ipvalue))

            # if index == 2 and not validSipv6 and not validSipv4: rcp_mess_block += self.mult_bytes_to_one_byte(4, len(validSipv6)) #当sipG为0需要配置长度为0
            # if index == 4 and not validDipv6 and not validDipv4: rcp_mess_block += self.mult_bytes_to_one_byte(4, len(validDipv6))
        rcp_mess_block += self.mult_bytes_to_one_byte(8,totalNum)
        rcp_mess_block += self.mult_bytes_to_one_byte(8, dayNum)
        rcp_mess_block += self.mult_bytes_to_one_byte(8, startTime)
        rcp_mess_block += self.mult_bytes_to_one_byte(8, endTime)
        #print(rcp_mess_block)
        return rcp_mess_block

    def addSniRule(self,serviceType,sniGroup=[[20,"www.baidu.com"]]):

        rcp_mess_block = []
        rcp_mess_block.append(self.dec_to_hex(serviceType))
        sniLen = len(sniGroup)
        rcp_mess_block.append(self.dec_to_hex(sniLen))
        rcp_mess_block += self.mult_bytes_to_one_byte(2, 0)
        if sniLen:
            for snivalue in sniGroup:
                rcp_mess_block.append(self.dec_to_hex(int(snivalue[0])))

                if int(snivalue[0])!= 1:
                    rcp_mess_block += self.mult_bytes_to_one_byte(int(snivalue[0]),self.str_process(snivalue[1]))
                else:
                    rcp_mess_block.append(self.mult_bytes_to_one_byte(int(snivalue[0]), self.str_process(snivalue[1])))
        return rcp_mess_block

    def samplingRule(self,samplePercent,outgroupId):
        """
        :param samplePercent: 采样百分比
        :param outgroupId: 输出端口组
        :return:
        """
        rcp_mess_block = []
        rcp_mess_block += self.mult_bytes_to_one_byte(2,samplePercent)
        rcp_mess_block += self.mult_bytes_to_one_byte(2,outgroupId)
        return rcp_mess_block

    def alarmSet(self,totalNumAlarmPercent,dayNumAlarmPercent,totalTimePercent):
        """
        :param totalNumAlarmPercent: 1B 总限量告警起始百分比
        :param dayNumAlarmPercent: 1B 日限量告警起始百分比
        :param totalTimePercent: 1B 放行时间告警起始百分比
        :return:
        """
        rcp_mess_block = []
        rcp_mess_block.append(self.dec_to_hex(totalNumAlarmPercent))
        rcp_mess_block.append(self.dec_to_hex(dayNumAlarmPercent))
        rcp_mess_block.append(self.dec_to_hex(totalTimePercent))
        rcp_mess_block.append(00)

        return rcp_mess_block

    def queryRuleRespondSuf(self,tranferTotal,dayTranfer,tranferTime,sniNumber,httpsPercent,notHttps):
        """

        :param tranferTotal: 4B 当前总传输量
        :param dayTranfer: 4B 当日已传输量
        :param tranferTime: 当前已放行时间
        :return:
        """
        rcp_mess_block = []
        rcp_mess_block += self.mult_bytes_to_one_byte(8,tranferTotal)
        rcp_mess_block += self.mult_bytes_to_one_byte(8,dayTranfer)
        rcp_mess_block += self.mult_bytes_to_one_byte(8,tranferTime)
        rcp_mess_block += self.mult_bytes_to_one_byte(8,sniNumber)
        rcp_mess_block += self.mult_bytes_to_one_byte(8,httpsPercent)
        rcp_mess_block += self.mult_bytes_to_one_byte(8,notHttps)

        return rcp_mess_block

    def queryRuleNumRespond(self,totalRuleNum,FxRule,ZdRule,AlarmRule,MirrRule):
        """
        查询各种类型的规则数量
        :param totalRuleNum: 总规则数量
        :param FxRule: 放行规则数量
        :param ZdRule: 阻断规则数量
        :param AlarmRule: 触发告警的规则数量
        :param MirrRule: 镜像规则数量
        :return:
        """
        rcp_mess_block = []
        rcp_mess_block += self.mult_bytes_to_one_byte(4, totalRuleNum)
        rcp_mess_block += self.mult_bytes_to_one_byte(4, FxRule)
        rcp_mess_block += self.mult_bytes_to_one_byte(4, ZdRule)
        rcp_mess_block += self.mult_bytes_to_one_byte(2, AlarmRule)
        rcp_mess_block += self.mult_bytes_to_one_byte(2, MirrRule)
        return rcp_mess_block

    def addSni(self,serviceType,sniNumber,httpsPercent,notHttps):
        """
        :param serviceType: 业务类型编码
        :param sniNumber: SNI数量阈值
        :param httpsPercent: 非HTTPS比例阈值
        :param notHttps: 非HTTPS阈值生效起始量(MByte)
        :return:
        """
        rcp_mess_block = []
        rcp_mess_block.append(self.dec_to_hex(serviceType))
        rcp_mess_block.append(self.dec_to_hex(sniNumber))
        rcp_mess_block.append(self.dec_to_hex(httpsPercent))
        rcp_mess_block.append(self.dec_to_hex(notHttps))

        return rcp_mess_block

if __name__ == '__main__':
    a = RcpPacketData()
    for i in range(255):
        c = a.ruleRelase('v4',("udp",123),sip=["192.168.2.3/12"],sport=[(1,5)],dip=["10.0.0.1/12"],dport=[(3,3)],totalNum=100,dayNum=0,startTime=100,endTime=100,changeFlag=4,ruleId=2)
    print(len(c))