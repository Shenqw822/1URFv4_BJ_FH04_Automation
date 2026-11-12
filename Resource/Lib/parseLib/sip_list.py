# from scapy.all import *
#
# def extract_five_tuple_from_pcap(pcap_file):
#     # 读取pcap文件
#     packets = rdpcap(pcap_file)
#
#     # 存储提取的五元组的列表
#     five_tuple_list = []
#
#     # 遍历每个数据包
#     for packet in packets:
#         # 检查是否有IP层
#         if IP in packet:
#             ip_layer = packet[IP]
#
#             # 获取五元组信息
#             src_ip = ip_layer.src
#             dst_ip = ip_layer.dst
#
#             # 根据协议类型提取端口信息
#             if TCP in ip_layer:
#                 protocol = 'TCP'
#                 src_port = ip_layer[TCP].sport
#                 dst_port = ip_layer[TCP].dport
#             elif UDP in ip_layer:
#                 protocol = 'UDP'
#                 src_port = ip_layer[UDP].sport
#                 dst_port = ip_layer[UDP].dport
#             else:
#                 # 如果是其他协议，可以根据实际情况进行处理
#                 protocol = 'Other'
#                 src_port = 0
#                 dst_port = 0
#
#             # 将五元组信息添加到列表中
#             five_tuple = (src_ip, src_port, dst_ip, dst_port, protocol)
#             five_tuple_list.append(five_tuple)
#
#     return five_tuple_list
#
# def del_value_from_list(data_list,index):
#     data_list.pop(int(index))
#     return data_list
#
# # 示例用法
# pcap_file_path = "stream2.pcap"
# result = extract_five_tuple_from_pcap(pcap_file_path)
# print("Extracted Five-Tuple:", result)

from scapy.all import Ether, IP, Raw, wrpcap

# 生成200个报文
num_packets = 200

# 构造Ethernet帧
eth_frame = Ether()

# 构造IP包，协议号为253
ip_packet = IP(proto=253)

# 构造Raw载荷，从第14字节开始为0x33333333
payload = Raw(load=b'\x00' * 13 + b'\x33\x33\x33\x33')

# 存储生成的报文
packets = []

# 构建每个报文，确保长度不低于100字节
# for _ in range(num_packets):
#     # 构建数据包
#     packet = eth_frame / ip_packet / payload
#
#     # 计算当前报文的总长度
#     current_length = len(packet)
#
#     # 如果长度不足100字节，添加额外的填充
#     while current_length < 100:
#         padding_length = min(100 - current_length, 20)  # 最多添加20字节的填充
#         packet /= Raw(load=b'\x00' * padding_length)
#         current_length = len(packet)
#
#     # 将构造的报文添加到列表中
#     packets.append(packet)
#
# # 将数据包写入pcap文件
# pcap_file_path = "output.pcap"
# wrpcap(pcap_file_path, packets)
#
# print(f"{num_packets}个报文已生成并写入Pcap文件：{pcap_file_path}")

from scapy.all import Ether, IP, TCP, Raw, wrpcap

# 生成200个报文
num_packets = 200

# 构造Ethernet帧
eth_frame = Ether()

# 构造IP包，协议号为6（TCP）
ip_packet = IP(proto=6)

# 构造TCP包
tcp_packet = TCP()

# 构造Raw载荷，从第14字节开始为0x33333333
payload = Raw(load=b'\x00' * 13 + b'\x33\x33\x33\x33')

# 存储生成的报文
packets = []

# 构建每个报文，确保长度不低于100字节
for _ in range(num_packets):
    # 构建数据包
    packet = eth_frame / ip_packet / tcp_packet / payload

    # 计算当前报文的总长度
    current_length = len(packet)

    # 如果长度不足100字节，添加额外的填充
    while current_length < 100:
        padding_length = min(100 - current_length, 20)  # 最多添加20字节的填充
        packet /= Raw(load=b'\x00' * padding_length)
        current_length = len(packet)

    # 将构造的报文添加到列表中
    packets.append(packet)

# 将数据包写入pcap文件
pcap_file_path = "output1.pcap"
wrpcap(pcap_file_path, packets)

print(f"{num_packets}个报文已生成并写入Pcap文件：{pcap_file_path}")




