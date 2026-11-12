*** Settings ***
Library           ExcelLibrary
Resource          ../Resource/Public/initConfiguration.txt
Resource          ../Resource/Public/sshKeywordSet.txt
Resource          ../Resource/Public/instrument.txt
Resource          ../Resource/Public/Ddevice.txt
Library           ../Resource/Lib/rcpLib/makePcapFile.py    ${localRawPcapPath}    ${ssh_server_raw_pcap_path}
Library           ../Resource/Lib/rcpLib/RcpApiForRf.py
Resource          ../Resource/Business/variable.txt

*** Test Cases ***
Default Action
    [Documentation]    1、验证global unknown放行部分非ip规则；
    ...    2、测试ethtype字段匹配；
    [Tags]    cli
    [Setup]
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    Default_Action
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}Default_Action/
    comment    配置全局默认策略
    New Connection Custom
    telnet.write    global unknown action forward outgroup_f 1
    telnet.write    show global
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    comment    按照excel依次打流，验证报文默认转发情况
    FOR    ${row}    IN RANGE    2    17
        comment    读取excel内容
        ${rule}    read cell data by name    ${sheetName}    A${row}
        ${hitpacket}    read cell data by name    ${sheetName}    B${row}
        ${default_action}    read cell data by name    ${sheetName}    C${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    D${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    E${row}
        comment    打流、校验结果(1、设备rx不为0，且tx=0；2、仪表rx=0；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    default_action_${row}_hit    ${hitpacket}    ${startFlowSpeed}    ${startFlowTime}    tcpreplayPath=${stream_name_pre}
        Run Keyword If    ${default_action} == 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    0    默认阻断的流量有输出
        ...    ELSE    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${tx}[0]    默认放行流量转发异常
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Continue For Loop If    ${default_action} == 0
        Comment    检验输出报文内容
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}Default_Action/    ${hitpacket}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    default_action_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
    END
    New Connection Custom
    telnet.write    global unknown action drop
    telnet.write    show global
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    comment    按照excel依次打流，验证l2 ethtype匹配情况
    FOR    ${row}    IN RANGE    17    ${countRrowAdd}
        comment    读取excel内容
        ${rulepre}    read cell data by name    ${sheetName}    A${row}
        ${hitpacket}    read cell data by name    ${sheetName}    B${row}
        ${appId}    read cell data by name    ${sheetName}    C${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    D${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    E${row}
        ${ruleSuf}    Set Variable    action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true
        ${acl_all}    catenate    ${rulePre}    ${ruleSuf}
        New Connection Custom
        telnet.write    ${acl_all}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    should not contain    ${info}    ERROR
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打流、校验结果(1、设备rx不为0，且tx=0；2、仪表rx=0；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ethtype_${row}_hit    ${hitpacket}    ${startFlowSpeed}    ${startFlowTime}    tcpreplayPath=${stream_name_pre}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${appId}
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}<=${inByte}    业务流的hitCount大等设备总接收
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}>=${outByte}    业务流的hitCount小于设备的txbyte
    END
    [Teardown]    undoAclAll
