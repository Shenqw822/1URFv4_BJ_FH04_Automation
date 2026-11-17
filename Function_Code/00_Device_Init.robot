*** Settings ***
Default Tags      init
Resource          ../Resource/Public/initConfiguration.txt
Resource          ../Resource/Business/variable.txt
Resource          ../Resource/Public/sshKeywordSet.txt

*** Variables ***
${restoreWaitTime}    10

*** Test Cases ***
deviceInit
    [Documentation]    设备初始化
    log    初始化设备
    comment    restore设备
    New Connection Custom
    telnet.write    restore default configuration
    sleep    ${restoreWaitTime}
    New Connection Custom
    telnet.write    show version
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    telnet.write    show acl all
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    comment    配置逻辑版类型以及对应端口up
    setLgtypeAndportUp
    comment    配置ingroup、outgroup
    ${ingroup_member}    create list    @{inportId}
    ${outgroup_member_1}    create list    @{outgroup_f_portId_1}
    ${ingroup_member_back}    create list    @{ingroup_back_port}
    #    ${inport_back}=    create list    @{inportId_back}
    addGroup    ingroup    ${ingroup_member}    ${ingroupId}    #用于vlan、mpls规则
    addGroup    outgroup_f    ${outgroup_member_1}    ${outgroup_fId_1}    #应对bug额外增加，实际无效果，用于命令行下发规则
    addGroup    ingroup    ${ingroup_member_back}    ${ingroup_back_id}
    #    addGroup    outgroup_f    ${outgroup_member_2}    ${outgroup_fId_2}
    log    其他特殊配置
    comment    配置linkmap
    ${ingroup_member_num}    Get Length    ${ingroup_member}
    ${outgroup_member_num}    Get Length    ${outgroup_member_1}
    Should Be EquaL    ${ingroup_member_num}    ${outgroup_member_num}    linkmap rx端口数量与tx数量不一致，无法一一对应
    FOR    ${i}    IN RANGE    ${ingroup_member_num}
        New Connection Custom
        telnet.write    linkmap rx ${inportId}[${i}] tx ${outgroup_f_portId_1}[${i}]
        telnet.read until    ${userName1}(config)#
        comment    部分为插模块的输出端口开启单纤使能
        telnet.write    interface eth ${outgroup_f_portId_1}[${i}] single_fiber true
        telnet.read until    ${userName1}(config)#
    END
    comment    配置设备ID（与RCP报文头deviceId保持一致）
    telnet.write    global device_id ${device_id}
    telnet.read until    ${userName1}(config)#
    comment    开启特征码规则开关
    telnet.write    global stage4_fixed_f enable
    telnet.read until    ${userName1}(config)#
    comment    设置流表相关的配置
    telnet.write    flow_manage tcp_aging_time 60
    telnet.read until    ${userName1}(config)#
    telnet.write    flow_manage udp_aging_time 60
    telnet.read until    ${userName1}(config)#
    telnet.write    flow_manage other_aging_time 60
    telnet.read until    ${userName1}(config)#
    telnet.write    flow_table aging_accuracy 8M
    telnet.read until    ${userName1}(config)#
    comment    关闭unknown和unhit
    telnet.write    undo global unhit
    telnet.read until    ${userName1}(config)#
    telnet.write    undo global unknown
    telnet.read until    ${userName1}(config)#
    comment    开启中标统计为byte
    telnet.write    global hit_count_byte enable
    telnet.read until    ${userName1}(config)#
    comment    配置白名单
    telnet.write    white_ip add ip ${rcp_client}
    telnet.read until    ${userName1}(config)#
    telnet.write    white_ip add ip ${trex_ip}
    telnet.read until    ${userName1}(config)#
    comment    查看ntp服务
    telnet.write    show interface mgmt 1/1
    telnet.read until    ${userName1}(config)#
    comment    查看全局配置
    telnet.write    show global
    ${info}    telnet.read until    ${userName1}(config)#
    log    ${info}
    comment    查看版本信息
    telnet.write    show version
    ${info}    telnet.read until    ${userName1}(config)#
    log    ${info}
    Set Global Variable    ${device_show_version_ref}    ${info}
    comment    查看当前时间
    telnet.write    show systemtime
    telnet.read until    ${userName1}(config)#
    comment    清除端口寄存器
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /home/
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo -n "mfpga${slot_id}(0x0,0xc20) mfpga${slot_id}(0x0,0xc21) mfpga${slot_id}(0x0,0xc22) mfpga${slot_id}(0x0,0xc23) mfpga${slot_id}(0x0,0xc24) mfpga${slot_id}(0x0,0xc25) mfpga${slot_id}(0x0,0xc26) mfpga${slot_id}(0x0,0xc27) mfpga${slot_id}(0x0,0xc28) mfpga${slot_id}(0x0,0xc29) mfpga${slot_id}(0x0,0xc2a) mfpga${slot_id}(0x0,0xc2b) mfpga${slot_id}(0x0,0xc2c) mfpga${slot_id}(0x0,0xc2d) mfpga${slot_id}(0x0,0xc2e) mfpga${slot_id}(0x0,0xc2f) mfpga${slot_id}(0x0,0xc30) mfpga${slot_id}(0x0,0xc40) mfpga${slot_id}(0x0,0xd30) mfpga${slot_id}(0x0,0xd31) mfpga${slot_id}(0x0,0xd32) mfpga${slot_id}(0x0,0xd33) mfpga${slot_id}(0x0,0xd34) mfpga${slot_id}(0x0,0xd35) mfpga${slot_id}(0x0,0xd36) mfpga${slot_id}(0x0,0xd37) mfpga${slot_id}(0x0,0xd38) mfpga${slot_id}(0x0,0xd39) mfpga${slot_id}(0x0,0xd3a) mfpga${slot_id}(0x0,0xd3b) mfpga${slot_id}(0x0,0xd3c) mfpga${slot_id}(0x0,0xd3d) mfpga${slot_id}(0x0,0xd3e) mfpga${slot_id}(0x0,0xe30) mfpga${slot_id}(0x0,0xe31) mfpga${slot_id}(0x0,0xe32) mfpga${slot_id}(0x0,0xe33) mfpga${slot_id}(0x0,0xe34) mfpga${slot_id}(0x0,0xe35) mfpga${slot_id}(0x00ff,0xc12)" | luacmd.lua
    sleep    1
    ${info}    SSHLibrary.Read Until    root@
    log    ${info}
    SSHLibrary.Close All Connections

instrumentInit
    log    初始化TCP replay服务器所存放的pcap文件
    comment    （0）清除服务器上的缓存的pcap文件
    OpenConnectionAndLogin    alias=hello
    SSHLibrary.Write    ifconfig \ ${ssh_server_net_port} mtu 9400
    sleep    2
    SSHLibrary.Write    rm -rf ${ssh_server_raw_pcap_path}
    sleep    2
    SSHLibrary.Write    rm -rf \ ${ssh_server_ripe_pcap_path}
    sleep    2
    SSHLibrary.Write    echo 3 > /proc/sys/vm/drop_caches
    sleep    2
    SSHLibrary.Write    rm -f /dev/shm/*.pcap
    sleep    2
    comment    关闭网卡vlan功能
    SSHLibrary.Write    ethtool \ -K \ \ ${ssh_server_net_port} rxvlan off txvlan off
    sleep    2
    comment    （1）ripe目录是tcpdump的输出目录：改用同步命令创建并当场校验。原来 Write mkdir 后立刻 Close All Connections，命令可能还没执行完会话就关了（Write 只读一行回显、不看返回码），日志里是 PASS 但目录实际没建出来，后续所有用例抓包失败
    ${out}=    SSHLibrary.Execute Command    mkdir -p ${ssh_server_ripe_pcap_path} && test -d ${ssh_server_ripe_pcap_path} && echo ok
    IF    'ok' not in '''${out}'''
        Fatal Error    打流服务器ripe目录创建失败: ${ssh_server_ripe_pcap_path}，终止运行
    END
    comment    （2）raw目录由本地 ${localRawPcapPath} 拷贝而来：目标目录不要预先创建，否则 Put Directory 会把源目录整个塞成子目录，tcpreplay 的路径就对不上；本地没有该目录或拷贝失败时 Put Directory 会抛异常，此处转成 Fatal Error 立即终止整个运行
    ${status}=    Run Keyword And Return Status    SSHLibrary.Put Directory    ${localRawPcapPath}    ${ssh_server_raw_pcap_path}    recursive=True
    IF    not ${status}
        Fatal Error    本地pcap拷贝到服务器失败: ${localRawPcapPath} -> ${ssh_server_raw_pcap_path}，终止运行
    END
    comment    操作完成后关闭所有ssh链接
    SSHLibrary.Close All Connections
