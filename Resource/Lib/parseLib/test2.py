##题目一
# def list_value_copy_zero_1(list_a,to_copy_value=0):
#     """
#     :param list_a: 输入的列表
#     :param to_copy_value: 列表中需要copy的元素，默认0
#     :return: 对输入列表中需要copy元素进行copy后输出
#     """
#     list_or_not = isinstance(list_a,list)
#     if list_or_not:
#         list_b = []
#         index_b=0
#         for index, value in enumerate(list_a):
#             list_b.append(value)
#             if value == to_copy_value:
#                 list_b.insert(index_b, to_copy_value)
#                 index_b += 1
#             index_b += 1
#         return list_b
#     else:
#         print("Argument Type Must List")
#
#
# def list_value_copy_zero_2(list_a,to_copy_value=0):
#     """
#     :param list_a: 输入的列表
#     :param to_copy_value: 列表中需要copy的元素，默认0
#     :return: 对输入列表中需要copy元素进行copy后输出"""
#
#     b = lambda list_a,to_copy_value:[x for x in list_a for y in range(1 if x!=0 else 2)]
#     return b(list_a,to_copy_value)
#
# if __name__ == "__main__":
#     list_a=[111,1001,1,0,1,0,0,11,0]
#     list_b = list_value_copy_zero_1(list_a,1)
#     print(list_b)
#
#     list_a = [1,0,2,3,0,4]
#     list_b = list_value_copy_zero_1(list_a,4)
#     print("%s==>%s"%(list_a,list_b))
#
#     list_a = [0,0,0,0]
#     list_b = list_value_copy_zero_1(list_a)
#     print("%s==>%s"%(list_a,list_b))
#
#     list_a = [100,10,0,101,1000]
#     list_b = list_value_copy_zero_2(list_a,101)
#     print("%s==>%s"%(list_a,list_b))
#
#     list_a = [100,10,0,101,1000]
#     list_b = list_value_copy_zero_2(list_a,0)
#     print("%s==>%s"%(list_a,list_b))

#题目二

#题目2
# def z_conver_normal(strings,row=3):
#    if row == 1:
#         return strings
#    gap = 2*row-2  #首行各元素之间的index差值
#    new_list = []
#    for row_index in range(row): #以行为单位进行循环
#        for index in range(row_index,len(strings),gap): #以每行在string中index提取对应元素
#            new_list.append(strings[index])
#        gap -= 2 #第2行在首行基础上减少2
#        if not gap:
#            if len(strings) == len(new_list): #因为首行、最后一行规律一样；这时候通过2个列表的长度是否一致判定是从头开始
#                break
#            else:
#                 gap = 2*row-2
#
#    return new_list
#
#
# c = "PAYPALISHIRING"
# result_list = z_conver_normal(c)
# print(''.join(result_list))
#
# import itertools
# # import math
import time
# # # a = [ 0  for x in range(12) ]
# # # b = [1,1]
# # # mask = a+b
# # #
# # # aaa= itertools.combinations(mask,3)
# # # # for i in aaa:
# # # #     print(i)
# # # from itertools import product,permutations
# # # # def test_func12(num_list):
# # # #     res_list = []
# # # #     for on
# # def factorial(n):
# #     if n == 0:
# #         return 1
# #     else:
# #         return n * factorial(n - 1)
# # def comb(n,k):
# #     if k > n:
# #         return 0
# #     else:
# #         return factorial(n) // factorial(n-k)// factorial(k)
# #
# # for i in range(1,32):
# #     sum = comb(32,i)*2**i
# #     if sum >=524288:
# #         print(comb(32, i))
# #         print(2 ** i)
# #         print(i)
# #         exit(1)
# list_t = [ x for x in range(1,33)]
# print(list_t)
# for i in list_t:
#     for j in list.remove(i)
a= [x for x in range(1,33)]
b= [x for x in range(2,33)]
c= [x for x in range(3,33)]
d= [x for x in range(4,33)]
mask_locate = [] #32bit中掩码的index,总共4bit掩码
for a1 in a:
    index_a1 = a.index(a1)
    for a2 in b[index_a1:]:
        index_a2 = b.index(a2)
        for a3 in c[index_a2:]:
            index_a3 = c.index(a3)
            for a4 in d[index_a3:]:
                ss = [str(a1),str(a2),str(a3), str(a4)]
                mask_locate.append(ss)
# print(mask_locate)
mask_list =[]
for hell in mask_locate:
    zero = [str(0) for x in range(32)]
    for sd in hell:
        zero[int(sd)-1] = str(1)
    tmp1 = zero[0:8]
    tmp2 = zero[8:16]
    tmp3 = zero[16:24]
    tmp4 = zero[24:32]
    zero1="".join(tmp1)
    zero2 = "".join(tmp2)
    zero3 = "".join(tmp3)
    zero4 = "".join(tmp4)
    mask_list.append(str(int(zero1,2))+"."+str(int(zero2,2))+"."+str(int(zero3,2))+"."+str(int(zero4,2)))

# print(mask_list)
ip_list =[]
ip_value="192.168.1.1" #"11000000101010000000000100000001"
# ip_value="111.111.111.111"#"01101111011011110110111101101111"
ip_value_tmp = int("11000000101010000000000100000001",2)
# ip_value_tmp = int("00010100000000000000000000000001") #20.0.0.1
# # # for mask_bit_list in mask_locate:
# # #     ip_value_list = [x for x in "11000000101010000000000100000001"]
# # #     for mask_bit1 in mask_bit_list:
# # #         index_1 = mask_bit_list.index(mask_bit1)+1
# # #         for value in [0, 1]:
# # #             ip_value_list[int(mask_bit1) - 1] = str(value)
# # #             for mask_bit2 in mask_bit_list[index_1:]:
# # #                 index_2 = mask_bit_list.index(mask_bit2)+1
# # #                 for value in [0, 1]:
# # #                     ip_value_list[int(mask_bit2 ) - 1] = str(value)
# # #                     for mask_bit3 in mask_bit_list[index_2:index_2]:
# # #                         index_3=mask_bit_list.index(mask_bit3)+1
# # #                         for value in [0, 1]:
# # #                             ip_value_list[int(mask_bit3) - 1] = str(value)
# # #                             for mask_bit4 in mask_bit_list[index_3:]:
# # #                                 for value in [0,1]:
# # #                                     ip_value_list[int(mask_bit4)-1]=str(value)
# # #                                     tmp1 = ip_value_list[0:8]
# # #                                     tmp2 = ip_value_list[8:16]
# # #                                     tmp3 = ip_value_list[16:24]
# # #                                     tmp4 = ip_value_list[24:32]
# # #                                     zero1="".join(tmp1)
# # #                                     zero2 = "".join(tmp2)
# # #                                     zero3 = "".join(tmp3)
# # #                                     zero4 = "".join(tmp4)
# # #                                     ip_list.append(str(int(zero1,2))+"."+str(int(zero2,2))+"."+str(int(zero3,2))+"."+str(int(zero4,2)))
for mask_bit_list in mask_locate:
    zero = [str(0) for x in range(32)]
    for sd in mask_bit_list:
        zero[int(sd) - 1] = str(1)
    tmp1 = zero[0:8]
    tmp2 = zero[8:16]
    tmp3 = zero[16:24]
    tmp4 = zero[24:32]
    zero1 = "".join(tmp1)
    zero2 = "".join(tmp2)
    zero3 = "".join(tmp3)
    zero4 = "".join(tmp4)
    mask1 = str(int(zero1, 2)) + "." + str(int(zero2, 2)) + "." + str(int(zero3, 2)) + "." + str(int(zero4, 2))
    # print(mask1)
    ip_value_tmp += 12800000
    ip_value_bin = bin(ip_value_tmp)[2:]
    ip_value_list = [x for x in ip_value_bin] #192.168.1.1
    # ip_value_list = [x for x in tmp1+tmp2+tmp3+tmp4]
    # print(ip_value_list)
    # ip_value_list = [x for x in "01101111011011110110111101101111"] #111.111.111.111
    # ip_value_list = ["0" for x in range(32)]
    for value in [0, 1]:
        ip_value_list[int(mask_bit_list[0])-1] = str(value)
        for value in [0, 1]:
            ip_value_list[int(mask_bit_list[1])-1] = str(value)
            for value in [0, 1]:
                ip_value_list[int(mask_bit_list[2])-1] = str(value)
                for value in [0,1]:
                    ip_value_list[int(mask_bit_list[3])-1]=str(value)
                    tmp1 = ip_value_list[0:8]
                    tmp2 = ip_value_list[8:16]
                    tmp3 = ip_value_list[16:24]
                    tmp4 = ip_value_list[24:32]
                    zero1="".join(tmp1)
                    zero2 = "".join(tmp2)
                    zero3 = "".join(tmp3)
                    zero4 = "".join(tmp4)
                    # print(str(int(zero1,2))+"."+str(int(zero2,2))+"."+str(int(zero3,2))+"."+str(int(zero4,2)))
                    ip_list.append(str(int(zero1,2))+"."+str(int(zero2,2))+"."+str(int(zero3,2))+"."+str(int(zero4,2))+"/"+mask1)
                    # ip_list.append(str(int(zero1,2))+"."+str(int(zero2,2))+"."+str(int(zero3,2))+"."+str(int(zero4,2)))
# print(len(ip_list))
# print(len(set(ip_list)))

#
with open("hhh.txt","w") as f:
    for i in ip_list:
        f.write("acl stage3_f ipmode ipv4 src_ip "+i+" action forward outgroup_f 1  hit_statistics true\n")