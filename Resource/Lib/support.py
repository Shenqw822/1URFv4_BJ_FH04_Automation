#_*_coding:utf-8_*_
import re

def delete_space(string):
    return string.replace(" ","").replace("\t","").strip()

def statistic(string):
    #返回参数statisticList[i]的列表内容：rx-pkts,rx-bytes,jumbo(oversinze),undersize,discard,fcsError,mtuExceeded,fragments,tx-pkts,tx-bytes
    statistcList = list()
    list1 = string.split("eth")
    del list1[0]

    for i in range(len(list1)):
        statistcList = list1[i].split(" ")
        del statistcList[0]
        while "" in statistcList:
            statistcList.remove("")

    return statistcList

def compare_lists(list1, list2):
    if all(item in list2 for item in list1):
        return "allocate"
    else:
        return "recount"

def compare_hash_lists(list1, list2):
    sets_are_equal = set(list1) == set(list2)
    if sets_are_equal:
        return True
    else:
        return False

def del_value_from_list(data_list,index):
    data_list.pop(int(index))
    return data_list

def Changeabs(number):
    return abs(number)

def discard_jk(string):
    string_list = string.split()
    discard_list = [0,0,0,0,0,0,0,0]
    discard_list[0]=(str(int(string_list[6])+int(string_list[54])))
    discard_list[1]=(str(int(string_list[12])+int(string_list[60])))
    discard_list[2]=(str(int(string_list[18])+int(string_list[66])))
    discard_list[3]=(str(int(string_list[24])+int(string_list[72])))
    discard_list[4]=(str(int(string_list[30])+int(string_list[78])))
    discard_list[5]=(str(int(string_list[36])+int(string_list[84])))
    discard_list[6]=(str(int(string_list[42])+int(string_list[90])))
    discard_list[7]=(str(int(string_list[48])+int(string_list[96])))
    return discard_list

def discard(string):
    string_list = string.split()
    discard_list = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    discard_list[0]=(str(int(string_list[6])))
    discard_list[1]=(str(int(string_list[12])))
    discard_list[2]=(str(int(string_list[18])))
    discard_list[3]=(str(int(string_list[24])))
    discard_list[4]=(str(int(string_list[30])))
    discard_list[5]=(str(int(string_list[36])))
    discard_list[6]=(str(int(string_list[42])))
    discard_list[7]=(str(int(string_list[48])))
    discard_list[8]=(str(int(string_list[54])))
    discard_list[9]=(str(int(string_list[60])))
    discard_list[10]=(str(int(string_list[66])))
    discard_list[11]=(str(int(string_list[72])))
    discard_list[12]=(str(int(string_list[78])))
    discard_list[13]=(str(int(string_list[84])))
    discard_list[14]=(str(int(string_list[90])))
    discard_list[15]=(str(int(string_list[96])))
    return discard_list

#10进制转换成16进制并补全2个字节
def intToHex(number):
    x = list(hex(number))
    x = x[2:]
    while(len(x)!=4):
        x.insert(0,'0')
    length = ''.join(x)
    print(length)
    return length
def hexToInt(number):
    length = int(number,16)
    return length  
def  splitSmacAndDmac(smac,dmac):
    '''
    删除mac地址中的‘：’，并返回DmacSmac格式

    :param smac: 8c:ec:4b:93:47:65

    :param dmac:0c:c4:7a:50:43:c0

    :return:0CC47A5043C08CEC4B934765
    
    '''
    smac = smac.replace(":","").strip().upper()
    dmac = dmac.replace(":","").strip().upper()
    return dmac+smac
def  splitSmacAndDmac(smac,dmac):
    '''
    删除mac地址中的‘：’，并返回DmacSmac格式

    :param smac: 8c:ec:4b:93:47:65

    :param dmac:0c:c4:7a:50:43:c0

    :return:0CC47A5043C08CEC4B934765
    
    '''
    smac = smac.replace(":","").strip().upper()
    dmac = dmac.replace(":","").strip().upper()
    return dmac+smac
    

if __name__=="__main__":
    # intToHex(18)
    list1=['efb0865578119caae9886f06b6ce71841bdb7f249762d8ac096a14a3d7c76131', '5a01918d590ca2655f9a8b36f71dbdb9dd81e4f10b6f4b5549b7fcc519a500f1', '5b7648ea45da745afac4b47e609691294bdc4e2b7c19e07b5ebb17d17ddd9728']
    list2=['efb0865578119caae9886f06b6ce71841bdb7f249762d8ac096a14a3d7c76131', '5a01918d590ca2655f9a8b36f71dbdb9dd81e4f10b6f4b5549b7fcc519a500f1', '5b7648ea45da745afac4b47e609691294bdc4e2b7c19e07b5ebb17d17ddd9728']
    # a = compare_hash_lists(list1,list2)
    # print(a)
    a = compare_lists(list1,list2)
    print(a)