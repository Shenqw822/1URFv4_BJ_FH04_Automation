*** Settings ***
Documentation     测试端口mtu，遍历64,9000,9400（服务器仪表最小发包64字节）
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
mtu
    [Tags]    cli
    Comment    设置入出口信息
    ${ingroup}    create list    @{inportId}
    ${outport}    create list    @{outgroup_f_portId_1}
    Comment    业务测试流程：下发的规则、发送的报文名称一半（规则和包名中有全局变量，全部放excel有问题）存放在excel中，逐行读取一一对应下发
    log    ---1.open excel---
    open excel    ${ImportFilepath}/${excelName}
    log    ---2.读取某个表格中的值---
    ${sheetName}    Set Variable    mtu
    ${count_row}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    Comment    下发规则
    New Connection Custom
    telnet.write    undo acl all
    ${info}    Telnet.Read
    sleep    1
    comment    设置报文路径
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}mtu/
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        log    mtu测试，第${row} 行
        ${rule_pre}    read cell data by name    ${sheetName}    A${row}
        ${stream_name_suf}    read cell data by name    ${sheetName}    B${row}
        ${out_flag}    read cell data by name    ${sheetName}    C${row}
        ${case_flag}    read cell data by name    ${sheetName}    D${row}
        ${appId}    read cell data by name    ${sheetName}    F${row}
        ${rule_suf}=    set variable    action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true
        set Local variable    ${acl}    ${EMPTY}
        ${acl_rule}=    catenate    ${rule_pre}    ${rule_suf}
        ${get_show}    Get Lines Containing String    ${rule_pre}    show
        ${get_service}    Get Lines Containing String    ${rule_pre}    mtu
        Run Keyword If    "${get_show}" == "" and "${get_service}" == ""    Set Local Variable    ${acl}    ${acl_rule}
        Run Keyword If    "${get_show}" != "" and "${get_service}" == ""    Set Local Variable    ${acl}    ${rule_pre} ${inportId[0]}
        Run Keyword If    "${get_service}" != ""    Set Local Variable    ${acl}    interface eth ${inportId[0]} ${rule_pre}
        telnet.write    ${acl}
        ${info}    Telnet.Read
        telnet.write    show acl all
        ${info}    Telnet.Read
        Run Keyword And Continue On Failure    should not contain    ${info}    ERROR    ${row}行规则下发失败
        Continue For Loop If    '${stream_name_suf}' == 'no'
        Comment    发送命中流
        ${stream_name}    catenate    SEPARATOR=    ${stream_name_pre}    ${stream_name_suf}
        ${rx}    ${tx}    tcpreplayAndTcpdump    mtu_${row}    ${stream_name}.pcap    0    0
        Comment    根据是否输出标识进行处理
        Run Keyword If    '${out_flag}' == 'no'    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx不等于0
        Run Keyword If    '${out_flag}' == 'yes'    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics_mtu    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Comment    读取app_id对应acl规则的命中计数
        ${hitCount}    getAclHitstatistics    ${appId}    5
        log    第${row}行 app_id=${appId} outFlag=${out_flag} hitCount=${hitCount}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${hitCount}    ${0}    命中统计应有计数，实际${hitCount}
        Continue For Loop If    '${out_flag}' == 'no'
        ${src_hash_list}=    hash_and_remove_duplicates_tcp    ${localRawPcapPath}    mtu/${stream_name_suf}.pcap
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates_tcp    ${localRipePcapPath}    mtu_${row}.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
    END
    [Teardown]    undo acl all
