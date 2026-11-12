#coding=utf-8
tlvdict={}
def TLVparser1(tlv,OtDict,keyName):
    """

    :param tlv: 去除头部和尾部46534C4B的tlv字段
    :param OtDict:protocolVal.txt中定义的字典Dict
    :param keyName:需要分析的字段的名称，调用请传入"type"
    :return:返回字典标识type是N+1/N+2,解析出tlv中字段的值，如下所示：
            {'type': 'N+2', 'UUID': '7FE35F6110170000282AB484139A8396', 'Portid': '0A14',..., 'length': '00A4'}
    """
    global tlvdict
    if keyName=='type':
        tlvdict={}
        print("here")
    while len(tlv)>0:
        print(tlv)
        #获取类型
        type1 =int(tlv[0:4],16)
        print(type1)
        # ADD IN 20211027——用于区分TLS服务端TLV(服务端TLV小类高位置为1，如8001，8015)
        if (32792 > type1 > 32768):
            type1 = type1 - 32768
            print(type1)
        if(type1==65535):
            tlv=tlv[4:]
            print(tlv)
            tlvdict["type"] ="N+1"
            continue
        if(type1==24 and "type" in tlvdict):
            if(OtDict[keyName][str(type1)]=='SESSION'):
                tlvdict["type"] = "N+2"
        ty = OtDict[keyName][str(type1)]
        print(ty)
        #获取长度,如果长度为0则抛出异常
        lengths = int(tlv[4:8],16)
        if lengths==0:
            raise Exception("Lenght of %s's TLV should not be 0."%ty)
        #获取值
        value = tlv[8:lengths*2+8]

        #如果对应字段没有相对应的字典，则直接加入tlvDict
        if ty in OtDict:
            tlvdict = TLVparser1(value, OtDict, ty)
        else:
            print("ty:"+ty)
            print(tlvdict.items())
            if(ty in tlvdict):
                val = tlvdict[ty] + value
            else:
                val = value
            tlvdict[ty] = val
        tlv = tlv[lengths * 2 + 8:]
    tlvdict2 = tlvdict.copy()
    tlvdict={}
    return tlvdict2



if __name__=="__main__":
    log ="tic"
    dict={"type": {"23": "OTHER", "22": "RuleId", "26": "TFTP", "17": "L2"},"L2":{"1": "mac", "2": "vlan", "3": "mpls", "4": "pw"},"OTHER":{"1": "TimeStamp", "2": "Portid"}}
    print(TLVparser1(log,dict,"type"))