*** Settings ***
Documentation     测试隧道识别和剥离功能
Suite Teardown
Resource          ../Resource/Business/variable.txt
Resource          ../Resource/Public/initConfiguration.txt
Resource          ../Resource/Public/TC500.txt
Library           ../Resource/Lib/parseLib/DdevieParsePacket.py    # 解析报文函数
Resource          ../Resource/Public/Ddevice.txt    # 针对D设备新增的关键字
Library           ExcelLibrary
Library           String
Resource          ../Resource/Public/sshKeywordSet.txt
Resource          ../Resource/Public/instrument.txt
Library           ../Resource/Lib/rcpLib/RcpApiForRf.py

*** Test Cases ***
00 tunnel identify
    [Setup]
    [Timeout]
    Comment    设置入出口信息
    ${ingroup}    create list    @{inportId}
    ${outport}    create list    @{outgroup_f_portId_1}
    Comment    业务测试流程：下发的规则、发送的报文名称一半（规则和包名中有全局变量，全部放excel有问题）存放在excel中，逐行读取一一对应下发
    log    ---1.open excel---
    open excel    ${ImportFilepath}/${excelName}
    log    ---2.读取某个表格中的值---
    ${sheetName}    Set Variable    tunnel_identify
    ${count_row}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    Comment    下发规则
    ${rule_suf}=    set variable    action ${action_info} outgroup_f ${outgroup_fId_1} hit_statistics true
    New Connection Custom
    telnet.write    undo acl all
    ${info}    Telnet.Read
    telnet.write    global tunnel_key inner
    ${info}    Telnet.Read
    sleep    1
    Run Keyword And Continue On Failure    should not contain    ${info}    ERROR    配置隧道内外层失败
    comment    设置报文路径
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}Tunnel_identify/
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        log    identify测试，第${row} 行
        ${rule_pre}    read cell data by name    ${sheetName}    A${row}
        ${stream_name_suf}    read cell data by name    ${sheetName}    B${row}
        ${out_flag}    read cell data by name    ${sheetName}    C${row}
        ${case_flag}    read cell data by name    ${sheetName}    D${row}
        ${acl_rule}=    catenate    ${rule_pre}    ${rule_suf}
        ${get_undo}    Get Lines Containing String    ${rule_pre}    undo
        ${get_service}    Get Lines Containing String    ${rule_pre}    global
        ${acl}    Set Variable If    "${get_undo}" == "" and "${get_service}" == ""    ${acl_rule}    ${rule_pre}
        telnet.write    ${acl}
        ${info}    Telnet.Read
        telnet.write    show acl all
        ${info}    Telnet.Read
        Run Keyword And Continue On Failure    should not contain    ${info}    ERROR    ${row}行规则下发失败
        Continue For Loop If    '${stream_name_suf}' == 'no'
        Comment    发送流量
        ${stream_name}    catenate    SEPARATOR=    ${stream_name_pre}    ${stream_name_suf}
        ${rx}    ${tx}    tcpreplayAndTcpdump    tunnel_identify_${row}    ${stream_name}.pcap    0    0
        Comment    根据是否输出标识进行处理
        Run Keyword If    '${out_flag}' == 'no'    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx不等于0
        Run Keyword If    '${out_flag}' == 'yes'    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Continue For Loop If    '${out_flag}' == 'no'
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    Tunnel_identify/${stream_name_suf}.pcap
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    tunnel_identify_${row}.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
    END
    [Teardown]    undo acl all

01 tunnel_strip
    [Setup]
    [Timeout]
    Run Keywords
    Comment    设置入出口信息
    ${inport}=    create list    @{inportId}
    ${outport}=    create list    @{outgroup_f_portId_1}
    Comment    业务测试流程：下发的规则、发送的报文名称一半（规则和包名中有全局变量，全部放excel有问题）存放在excel中，逐行读取一一对应下发
    log    ---1.open excel---
    open excel    ${ImportFilepath}/${excelName}
    log    ---2.读取某个表格中的值---
    ${sheetName}    Set Variable    tunnel_strip
    ${count_row}    get row count    ${sheetName}    #去掉gre报文的route=1
    ${countRrowAdd}    Evaluate    ${count_row}+1
    New Connection Custom
    comment    打开全局开关
    telnet.write    global tunnel_strip \ enable
    sleep    1
    telnet.write    global tunnel_key \ inner
    ${info}    telnet.read
    Run Keyword And Continue On Failure    should not contain    ERROR    ${info}
    Comment    下发规则
    ${rule_suf}=    set variable    action strip_infomac outgroup_f ${outgroup_fId_1} hit_statistics true
    comment    设置报文路径
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}Tunnel_strip/
    FOR    ${row}    IN RANGE    2    ${count_row}
        log    strip测试，第${row}行
        ${rule_pre}    read cell data by name    ${sheetName}    A${row}
        ${stream_name_suf}    read cell data by name    ${sheetName}    B${row}
        ${out_flag}    read cell data by name    ${sheetName}    C${row}
        ${case_flag}    read cell data by name    ${sheetName}    D${row}
        ${correct}    Run Keyword If    '${out_flag}' == 'yes'    read cell data by name    ${sheetName}    E${row}
        ${acl_rule}=    catenate    ${rule_pre}    ${rule_suf}
        ${get_undo}    Get Lines Containing String    ${rule_pre}    undo
        ${get_service}    Get Lines Containing String    ${rule_pre}    global
        ${acl}    Set Variable If    "${get_undo}" == "" and "${get_service}" == ""    ${acl_rule}    ${rule_pre}
        telnet.write    ${acl}
        ${info}    Telnet.Read
        Run Keyword And Continue On Failure    should not contain    ${info}    ERROR    ${row}行规则下发失败
        New Connection Custom
        Continue For Loop If    '${stream_name_suf}' == 'no'
        Comment    发送流量
        ${stream_name}    catenate    SEPARATOR=    ${stream_name_pre}    ${stream_name_suf}
        ${rx}    ${tx}    tcpreplayAndTcpdump    tunnel_strip_${row}    ${stream_name}    0    0
        Comment    根据是否输出标识进行处理
        Run Keyword If    '${out_flag}' == 'no'    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx不等于0
        Run Keyword If    '${out_flag}' == 'yes'    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Continue For Loop If    '${out_flag}' == 'no'
        ${src_hash_list}=    hash_packets_except_smac    ${localRawPcapPath}Tunnel_strip/${correct}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_packets_except_smac    ${localRipePcapPath}tunnel_strip_${row}.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
    END
    New Connection Custom
    comment    关闭全局开关
    telnet.write    global tunnel_strip \ disable
    sleep    1
    telnet.write    undo global tunnel_key
    sleep    1
    [Teardown]    undo acl all

GRE_tunnel
    [Documentation]    最新仅支持内/外
    [Tags]    debug
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    GRE_Tunnel
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    comment    按照excel中的行为单位进行循环测试
    ${appid_list}    Create List
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}GRE_Tunnel/
    New Connection Custom
    telnet.write    global stage2_f_flexible enable
    FOR    ${row}    IN RANGE    2    22
        comment    读取excel内容
        ${ConfigOriniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitPcapname}    read cell data by name    ${sheetName}    H${row}
        ${backPcapname}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        comment    配置下发
        #    New Connection Custom
        Run Keyword If    "global" in "${ConfigOriniRcpFileName}" or "undo" in "${ConfigOriniRcpFileName}"    telnet.write    ${ConfigOriniRcpFileName}
        #    Run Keyword If    "undo" in "${ConfigOriniRcpFileName}" and ""    telnet.write    ${ConfigOriniRcpFileName}
        Continue For Loop If    "global" in "${ConfigOriniRcpFileName}" or "undo" in "${ConfigOriniRcpFileName}"
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${ConfigOriniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Append To List    ${appid_list}    ${ruleId}
        log    ${appid_list}
        comment    cli下规则查看
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    '${hitPcapname}' == 'no'
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    GRE_Tunnel_${row}_back    ${stream_name_pre}${backPcapname}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${PcapFileList}    Split String    ${hitPcapname}    ,
        log    ${PcapFileList}
        ${pcapnum}    Get Length    ${PcapFileList}
        ${rx}    ${tx}    tcpreplayAndTcpdump    GRE_Tunnel_${row}_hit_1    ${stream_name_pre}${PcapFileList}[0]    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword if    ${pcapnum}== 2    getAclHitstatistics    ${appid_list}[-2]
        ...    ELSE    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备总输入
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    GRE_Tunnel/${PcapFileList}[0]
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    GRE_Tunnel_${row}_hit_1.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
        Continue For Loop If    ${pcapnum}== 1
        log    ${appid_list}[-2]
        ${rx}    ${tx}    tcpreplayAndTcpdump    GRE_Tunnel_${row}_hit_2    ${stream_name_pre}${PcapFileList}[1]    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备总输入
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    GRE_Tunnel/${PcapFileList}[1]
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    GRE_Tunnel_${row}_hit_2.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
    END
    telnet.write    global stage2_f_flexible disable
    [Teardown]    runkeywords    undo acl all
    ...    AND    send_cli_command    undo global tunnel_key
