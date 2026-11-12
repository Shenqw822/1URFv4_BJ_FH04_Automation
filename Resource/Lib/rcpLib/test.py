#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2024/3/22:14:29
# email:peiwenping@finslink.com
# import paramiko_client
from functools import reduce
import time
#
# ssh = paramiko_client.ParamikoConnection('192.168.11.97',user='root',pwd='ubuntu')
# ssh.upload("c:/users/peiwe/desktop/0508.pcap","/home/0508.pcap")
# ssh.close()
# """
# 有四个数字：1、2、3、4，能组成多少个互不相同且无重复数字的三位数？各是多少？
# """
# a = range(1,5)
# count = 0
# num = []
# for i in a:
#     for j in filter(lambda x:x != i,a):
#         for k in filter(lambda x: x!=i and x !=j,a):
#             count += 1
#             num.append("{bai}{shi}{ge}".format(bai=i,shi=j,ge=k))
# print("总共{}个，分别是{}".format(count,' '.join(num)))

"""
企业发放的奖金根据利润提成
利润(I)低于或等于10万元时，奖金可提10%；
利润高于10万元，低于20万元时，低于10万元的部分按10%提成，高于10万元的部分，可提成7.5%；
20万到40万之间时，高于20万元的部分，可提成5%；
40万到60万之间时高于40万元的部分，可提成3%；
60万到100万之间时，高于60万元的部分，可提成1.5%，
高于100万元时，超过100万元的部分按1%提成，
从键盘输入当月利润I，求应发放奖金总数？
"""
# bonus = [lambda x:x * 0.1,
#          lambda x:1 + (x - 10) * 0.075,
#          lambda x:1.75 + (x - 20) * 0.05,
#          lambda x:2.75 + (x - 40) * 0.03,
#          lambda x:3.35 + (x - 60) * 0.015,
#          lambda x:3.95 + (x - 100) * 0.01]
# jie = [10, 20, 40, 60, 100]
# shu = 101
# hello = list(filter(lambda x: x < shu, jie))
# bonus_fun = bonus[len(hello)]
# print(len(hello))
# print("{}万的业绩，奖金为{}元".format(shu, bonus_fun(shu) * 10000))
#
# """
# 一个整数，它加上100后是一个完全平方数，再加上168又是一个完全平方数，请问该数是多少？
# """
# #等差数列21=100
# ss=[]
# dd = dict(zip(range(21,10000,2),range(10,2000)))
# def ll(start,count):
#     d = reduce(lambda x,y:x+y,range(start,10000,2)[:count])
#     return d
#     # print(d)
# for i in range(1,1000,2):
#     for count in range(1,7):
#         if ll(i,count) == 168:
#             ss.append(i)
# shu = []
# for fc in ss:
#     shu.append(pow(dd[fc],2)-100)
# # print(shu)
# #
# print("该数为:{}".format(",".join([str(x) for x in shu])))


# """
# 输入某年某月某日，判断这一天是这一年的第几天？
# """
#
# yearMonDay = input("请输(年/月/日):")
# try:
#     ymd_l = [ int(x) for x in yearMonDay.split('/')]
#     year = ymd_l[0]
#     mon = ymd_l[1]
#     day = ymd_l[2]
#     #判断闰年
#     shang,yu = divmod(year,100)
#     if yu:
#         shang1,yu1 = divmod(year,4)
#         if yu1:
#             yearHaveDays = 365
#         else:
#             yearHaveDays = 366
#     elif divmod(shang,4)[1]:
#         yearHaveDays = 365
#     else:
#         yearHaveDays = 366
#     # print("{}该年有{}天".format(yearMonDay,yearHaveDays))
#
#     #判断月
#     monDayList = [ 31,28,31,30,31,30,31,31,30,31,30,31] if yearHaveDays==365 else  [ 31,29,31,30,31,30,31,31,30,31,30,31]
#     Days = sum([monDayList[x] for x in range(mon-1)],day)
#     print("{}为{}年的第{}天".format(yearMonDay,year,Days))
# except:
#     print("Please Check Date Format")

###输入三个整数x,y,z，请把这三个数由小到大输出。
# threeS = input("请输入3个数(x,y,z):")
# try:
#     threeI = [int(i) for i in threeS.split(',')]
#     maxI = max(threeI)
#     minI = min(threeI)
#     zhong = [i for i in threeI if i not in [maxI,minI]]
#     print("{}从大到小排序{}>{[0]}>{}".format(threeS,maxI,zhong,minI))
#
# except:
#     print("Please Check Date Format must be {}".format("x,y,z"))

###斐波那契数列

# a=[55,89]
# for i in range(10):
#     a.append(reduce(lambda x,y:x+y,a[-2:]))
# print(a)

#输出 9*9 乘法口诀表。
# for i in range(1,10):
#     print()
#     for j in range(1,i+1):
#         print("{:>5d}{:>2s}{:>2d}{:>2s}{:>3d}".format(j,'*',i,'=',i*j),end=' ')
#
#打印出所有的"水仙花数"，所谓"水仙花数"是指一个三位数，其各位数字立方和等于该数本身。例如：135是一个"水仙花数"，因为153=1的三次方＋5的三次方＋3的三次方
# def hello(x):
#     y = str(x)
#     if x ==  pow(int(y[0]),3)+pow(int(y[1]),3)+pow(int(y[2]),3):
#         return x
# shuixiu = filter(hello,range(100,1000))
# print(list(shuixiu))

from scapy.all import *

# ipList = Ether() / IP(src="192.168.1.1/28")
# print(ipList[0].show())
#给文本增加拼音
# from  pypinyin import pinyin
# r=pinyin('我爱北京天安门')
# print(r)
# print(" ".join([i[0] for i in pinyin("你好")]))
# print(" ".join([i[0] for i in pinyin("好客")]))


text = '''石室诗士施氏，嗜狮，誓食十狮。施氏时时适市视狮。
十时，适十狮适市。是时，适施氏适市。施氏视是十狮，恃矢势，使是十狮逝世。
氏拾是十狮尸，适石室。石室湿，氏使侍拭石室。石室拭，施氏始试食是十狮尸。
食时，始识是十狮尸，实十石狮尸。试释是事。
 '''
# # print(list(text))
# new = []
# for char in text:
#     print("{: >5}".format(pinyin(char)[0][0]),end="")
#     new.append(char)
#     if char == '\n':
#         # print("====",new)
#         for x in new:
#             print("{:>4}".format(x),end='')
#             if x == '\n':new = [];print();continue
#而pyttsx3是一个专注于让计算机朗读文字的编程库

# for i in range(1,10):
#     for j in range(1,i+1):
#         print("{:>2}x{:>2}={:>2}".format(j,i,i*j),end = '')
#     print()
# list1 = []
# for i in range(1,14):
#     for j in range(i,14):
#         for k in range(j,14):
#             for l in range(k,14):
#                 a = i+j+k+l
#                 if a == 14:
#                     list1.append([i,j,k,l])
# print(list1)
# print(len(list1))

# for i in range(10):
#     print(i)
#     continue
# else:
#     print("else下的{}".format(i))
# wan = []
# for i in range(1,10001):
#     a = 0
#     for j in range(1,i):
#         if i%j ==0:
#             a+=j
#     if i == a:
#         wan.append(i)
# print(wan)
# def shu(wei):
#     shui = []
#     wei = int(wei)
#     for i in range(10**(wei-1),10**wei):
#         san = list(str(i))
#         san_li = map(lambda x:int(x)**wei,san)
#         if i == sum(san_li):
#             shui.append(i)
#     return shui
# a = shu(5)
# print(a)

# m = 1
# while m**3 <=87539319:
#     n = m
#     while n**3 <=87539319:
#         if m**3 + n**3 == 87539319:
#             print(m,n)
#             break
#         n += 1
#     m += 1


# for i in range(100,1000):
#     s = []
#     if len(set(str(i)))<3:continue
#     i_list = list(str(i))
#     cha = int("".join(sorted(i_list))) - int("".join(sorted(i_list,reverse=True)))
#     if cha == 495:
#         s.append(i)

# import itertools
# print(itertools.count(5,10))

# import random
#
# idioms = ['平易近人','宽宏大度','冰清玉洁','持之以恒','锲而不舍',
# '废寝忘食','大义凛然','临危不惧','光明磊落','不屈不挠',
# '鞠躬尽瘁','死而后已','高山仰止','嫉恶如仇','国泰民安']
#
#
# def genTest():
#     idiom = random.choice(idioms)
#     kw = random.choice(idiom)
#     pidiom = idiom.replace(kw,'__',1)
#     return idiom,kw,pidiom
# goal = 0
# while goal <60:
#     idiom,kw,pidiom = genTest()
#     count = 0
#     while  count<3:
#         gw = input("请把'{}'补充完整：".format(pidiom) )
#         if gw == kw:
#             goal += 10
#             print("太棒了，当前分数:{}!成语是{}".format(goal,idiom))
#             break
#         count += 1
#     else:
#         print("太可惜！成语是{}".format(idiom))
# else:
#     print('顺利闯关')

# import re
# p = '^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])[0-9a-zA-z]{6,8}'
# pr = re.compile(p)
#
# while True:
#     times = 0
#     while times<3:
#         guess = input("请输入密码：")
#         if pr.findall(guess):
#             print("密码符合预期")
#             break
#         else:
#             times += 1
#             print("{}次数密码不符合要求".format(times))
#     break

# import qrcode
# s = "中华人民共和国"
# img = qrcode.make(s)
# img.save("C:\\Users\\peiwe\\Desktop\\001.png")

# import urllib.request
# import bs4
# f = urllib.request.urlopen("http://www.baidu.com")
# heml_doc = f.read().decode('utf-8')
# soup = bs4.BeautifulSoup(heml_doc,'html.parser')
# print(soup.get_text())
# for link in soup.find_all('a'):
#     print(link.get('href'))

# import numpy as np
# GCS ='XO'
# puz = np.zeros((3,3),dtype=np.str)
# puz[:]='-'
# right = 0
# steps =[(1,1),(0,0),(2,1),(1,2),(2,0),(1,0)]
# for step in steps:
#     x,y = step
#     puz[x,y] = GCS[right]
#     right = right^1
# print(puz)

##网站验证码

#
# from PIL import Image,ImageDraw,ImageFont,ImageFilter
# import random
#
# def rndChar(): #生成随机数
#     return chr(random.randint(65,90))
# def rndColor(m,n): #生成随机颜色
#     return tuple(random.randint(m,n) for i in range(3))
#
# image = Image.new('RGB',(440,60),(255,255,255)) #白色背景图
# font = ImageFont.truetype('arial.ttf',36) #所用字体
# draw = ImageDraw.Draw(image)
# for x in range(440): #绘制随机颜色点
#     for y in range(60):
#         draw.point((x,y),fill=rndColor(64,255))
# for t in range(7): #输出文字
#     draw.text((40*t+20,10),rndChar(),font=font,fill=rndColor(32,128))
# image = image.filter(ImageFilter.BLUR) #调用滤镜,实现模糊化
# image.show()


#让计算机学习某种风格的艺术作品，然后就可以让它依据那种风格，改编其他图像了

#人脸识别安装opencv，pip3 install -i  https://pypi.doubanio.com/simple/  opencv-python

# import cv2
#
# #检查面部函数，参数img为图像数据
# def detect_face(classifier,imgfile):
#     img = cv2.imread(imgfile,cv2.IMREAD_GRAYSCALE)#灰度图方式读取图像
#     faces = classifier.detectMultiScale(img)
#     #返回检测到的面部数据
#     x,y,w,h = faces[0]
#     return img[y:y+h,x:x+w]
# #加载已有的模型
# # path = "C:\\Users\\peiwe\\AppData\\Local\\Programs\\Python\\Python35\\Lib\\site-packages\\cv2\\data\\"
# # classifier = cv2.CascadeClassifier(path + 'haarcascade_frontalface_default.xml')
# classifier = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
#
# face = detect_face(classifier,"pic\\abc.jpg")
# cv2.imshow("image",face)#显示图片
# cv2.waitKey(1000)
# cv2.destroyAllWindows()

# time1 = time.time()
# a = (-2)**1000
# print(a)
# time2 = time.time()
# print(time2-time1)
# zuhe = []
# for x in range(61):
#     for y in range(61):
#         for z in range(61):
#             if x +2*y +5*z == 180 and x +y +z ==60:
#                 zuhe.append("{},{},{}".format(x,y,z))
# print(zuhe)
# print(len(zuhe))
# print(len(set(zuhe)))
# import time
# import datetime
# def cli_time_epoc_switchRcp( time1, format=0, interval_time=0):
#     """
#     设备时间和unix时间相互转换，并且增加上间隔时间
#     :param time1: 要不unix，要不就是设备系统时间
#     :param format:0:返回设备时间格式，1返回unix时间
#     :param interval_time: 以秒为单位，在time1的基础上增加该时长
#     :return:
#     """
#     if '-' in str(time1):
#         time_get = datetime.datetime.strptime("%s" % time1, "%Y.%m.%d-%H:%M:%S")
#         time1_unix = time.mktime(time_get.timetuple())
#         time1_unix_interval = int(time1_unix) + int(interval_time)
#     else:
#         time1_unix_interval = int(time1) + int(interval_time)
#     if not format:
#         time2 = datetime.datetime.fromtimestamp(time1_unix_interval)
#         device_time = time2.strftime("%Y.%m.%d-%H:%M:%S")
#         return device_time
#     else:
#         return time1_unix_interval
#
# a = cli_time_epoc_switchRcp(28149,0,0)
# print(a)

# r = []
# for x in range(7):
#     for y in range(7):
#         r.append((x,y))
#
# import itertools
# solutions = itertools.combinations(r,8)
#
# result = []
#
# for solution in solutions:
#     xs = {grid[0] for grid in solution}
#     if len(xs) !=8 :continue
#     ys = {grid[1] for grid in solution}
#     if len(ys) !=8 :continue
#     ds1 = {grid[0] - grid[1] for grid in solution}
#     if len(ds1) != 8: continue
#     ds2 = {grid[0] + grid[1] for grid in solution}
#     if len(ds2) !=8 : continue
#     result.append(solution)
# print(result)

#
# import itertools
# solutions = itertools.permutations([0,1,2,3,4,5,6,7],8)
# result = []
# for solution in solutions:
#     ds1 = set((x+y) for x,y in enumerate(solution))
#     if len(ds1) !=8 :continue
#     ds2 = set((x-y) for x,y in enumerate(solution))
#     if len(ds2) !=8:continue
#     result.append(solution)
# print(len(result))
# import dpkt
# from scapy.all import *
# import binascii
# import os
# import time
# import zlib
#
# # radius_type = {
# #     1: "Access-Request",
# #     2: "Access-Accept",
# #     3: "Access-Reject",
# #     4: "Accounting-Request",
# #     5: "Accounting-Response",
# #     6: "Accounting-Status (now Interim Accounting)",
# #     7: "Password-Request",
# #     8: "Password-Ack",
# #     9: "Password-Reject",
# #     10: "Accounting-Message",
# #     11: "Access-Challenge",
# #     12: "Status-Server (experimental)",
# #     13: "Status-Client (experimental)",
# #     21: "Resource-Free-Request",
# #     22: "Resource-Free-Response",
# #     23: "Resource-Query-Request",
# #     24: "Resource-Query-Response",
# #     25: "Alternate-Resource-Reclaim-Request",
# #     26: "NAS-Reboot-Request",
# #     27: "NAS-Reboot-Response",
# #     28: "Reserved",
# #     29: "Next-Passcode",
# #     30: "New-Pin",
# #     31: "Terminate-Session",
# #     32: "Password-Expired",
# #     33: "Event-Request",
# #     34: "Event-Response",
# #     40: "Disconnect-Request",
# #     41: "Disconnect-ACK",
# #     42: "Disconnect-NAK",
# #     43: "CoA-Request",
# #     44: "CoA-ACK",
# #     45: "CoA-NAK",
# #     50: "IP-Address-Allocate",
# #     51: "IP-Address-Release",
# #     52: "Protocol-Error",
# #     250: "Experimental Use",
# #     251: "Experimental Use",
# #     252: "Experimental Use",
# #     253: "Experimental Use",
# #     254: "Reserved",
# #     255: "Reserved"
# # }
# #
# # dd = re.compile("\\S{2,2}")
# #
# # def add_crc(path="C:\\Users\\peiwe\\Desktop\\test",sep="win"):
# #     sep = '\\' if 'win' in str(sep).lower() else '/'
# #     for home, folder, files in os.walk(path):
# #         for file in files:
# #             if ".pcap" not in  file: continue
# #             pkindex = 0
# #             index = []
# #             value = []
# #             with  open(home + sep + file,'rb') as fi:
# #                 hello1 = dpkt.pcap.Reader(fi)
# #                 for timestamp,pkt in hello1:
# #                     dest_data = b''
# #                     pkindex += 1
# #                     cc = str(binascii.hexlify(pkt),encoding="utf-8")[0:-8]
# #                     ddd = bytes(bytes(str(binascii.hexlify(pkt),encoding="utf-8"),encoding="utf-8"))[0:-8]
# #                     crc = hex(binascii.crc32(binascii.a2b_hex(ddd))&0xffffffff)
# #                     crc_quan = "{:0>8}".format(crc[2:])
# #                     crc_quan_two = [crc_quan[i:i+2] for i in range(0,len(crc_quan),2)]
# #                     crc_fin = "".join(list(reversed(crc_quan_two)))
# #                     # print(ddd + bytes(crc_fin,encoding="utf-8"))
# #                     add_crc_packet = cc +crc_fin
# #                     newhelloList = [add_crc_packet[x:x + 2] for x in range(0, len(add_crc_packet), 2)]
# #                     print(newhelloList)
# #                     for dest in newhelloList:  # 主要是对字符串转为符合网络传送的bytes格式
# #                         dest_t = int(str(dest), 16)
# #                         dest_data += struct.pack('B', dest_t)
# #                     value.append(dest_data)
# #             if value:
# #                 wrpcap("{}{}new_{}".format(home,sep, file), value)
# #             else:
# #                 wrpcap("{}{}new_{}".format(home, sep, file), value)
# #
# #
# # if __name__ == '__main__':
# #     time1 = time.time()
# #     path = "C:\\Users\\peiwe\\Desktop\\test"
# #     time1 = time.time()
# #     c = add_crc(path)
# #     tim = time.time()
# #     print(tim-time1)
# #     input("执行完毕，输入任意键结束")
#
#
#
# radius_type = {
#     1: "Access-Request",
#     2: "Access-Accept",
#     3: "Access-Reject",
#     4: "Accounting-Request",
#     5: "Accounting-Response",
#     6: "Accounting-Status (now Interim Accounting)",
#     7: "Password-Request",
#     8: "Password-Ack",
#     9: "Password-Reject",
#     10: "Accounting-Message",
#     11: "Access-Challenge",
#     12: "Status-Server (experimental)",
#     13: "Status-Client (experimental)",
#     21: "Resource-Free-Request",
#     22: "Resource-Free-Response",
#     23: "Resource-Query-Request",
#     24: "Resource-Query-Response",
#     25: "Alternate-Resource-Reclaim-Request",
#     26: "NAS-Reboot-Request",
#     27: "NAS-Reboot-Response",
#     28: "Reserved",
#     29: "Next-Passcode",
#     30: "New-Pin",
#     31: "Terminate-Session",
#     32: "Password-Expired",
#     33: "Event-Request",
#     34: "Event-Response",
#     40: "Disconnect-Request",
#     41: "Disconnect-ACK",
#     42: "Disconnect-NAK",
#     43: "CoA-Request",
#     44: "CoA-ACK",
#     45: "CoA-NAK",
#     50: "IP-Address-Allocate",
#     51: "IP-Address-Release",
#     52: "Protocol-Error",
#     250: "Experimental Use",
#     251: "Experimental Use",
#     252: "Experimental Use",
#     253: "Experimental Use",
#     254: "Reserved",
#     255: "Reserved"
# }
#
# dd = re.compile("\\S{2,2}")
#
# def add_crc(path="C:\\Users\\peiwe\\Desktop\\test",sep="win",has_crc=None):
#     sep = '\\' if 'win' in str(sep).lower() else '/'
#     for home, folder, files in os.walk(path):
#         for file in files:
#             if "2.pcap" not in  file: continue
#             pkindex = 0
#             value = []
#             with  open(home + sep + file,'rb') as fi:
#                 hello1 = dpkt.pcap.Reader(fi)
#                 for timestamp,pkt in hello1:
#
#                     dest_data = b''
#                     pkindex += 1
#                     cc = str(binascii.hexlify(pkt),encoding="utf-8")[0:-8]
#                     ddd = bytes(bytes(str(binascii.hexlify(pkt),encoding="utf-8"),encoding="utf-8"))[0:-8]
#                     crc = hex(binascii.crc32(binascii.a2b_hex(ddd))&0xffffffff)
#                     crc_quan = "{:0>8}".format(crc[2:])
#                     crc_quan_two = [crc_quan[i:i+2] for i in range(0,len(crc_quan),2)]
#                     crc_fin = "".join(list(reversed(crc_quan_two)))
#                     print(crc_fin)
#                     # print(ddd + bytes(crc_fin,encoding="utf-8"))
#                     add_crc_packet = cc +crc_fin
#                     newhelloList = [add_crc_packet[x:x + 2] for x in range(0, len(add_crc_packet), 2)]
#                     # print(newhelloList)
#                     for dest in newhelloList:  # 主要是对字符串转为符合网络传送的bytes格式
#                         dest_t = int(str(dest), 16)
#                         dest_data += struct.pack('B', dest_t)
#                     value.append(dest_data)
#             if value:
#                 wrpcap("{}{}new_{}".format(home,sep, file), value)
#             else:
#                 wrpcap("{}{}new_{}".format(home, sep, file), value)
#
#
# if __name__ == '__main__':
#     time1 = time.time()
#     path = "C:\\Users\\peiwe\\Desktop\\test"
#     time1 = time.time()
#     c = add_crc(path,"win",True)
#     tim = time.time()
#     print(tim-time1)
#     input("执行完毕，输入任意键结束")
import struct
