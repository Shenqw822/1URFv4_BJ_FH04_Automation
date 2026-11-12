*** Settings ***
Documentation     1、配置生效
...               2、配置修改
...               3、流量阻断
...               4、告警、日志上报
Default Tags      cli
Library           ExcelLibrary
Resource          ../Resource/Public/initConfiguration.txt
Resource          ../Resource/Public/sshKeywordSet.txt
Resource          ../Resource/Public/instrument.txt
Resource          ../Resource/Public/Ddevice.txt
Library           ../Resource/Lib/rcpLib/RcpApi.py    ${host_ip}

*** Variables ***
${wuCha}          3

*** Test Cases ***
totalNumTest
    [Documentation]    测试点：1、配置生效；2、配置修改；3、告警上报
    ...
    ...    20260903新增：阻断后修改组合关系//已知问题：阻断后变更，没有限量效果
    [Setup]    undoAclAll
    log    测试放行用例
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    totalNum
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${totalAcl}    Set Variable    0
    ${totalAppIdList}    Create List
    ${backPcafileSuf}    Set Variable    back.pcap
    ${ingroup_member}    create list    @{inportId}
    ${ingroup_member_num}    Get Length    ${ingroup_member}
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        log    第${row}行循环测试
        comment    获取相关内容
        ${rulePre}    read cell data by name    ${sheetName}    A${row}
        ${appId}    read cell data by name    ${sheetName}    B${row}
        ${pcapfileOrNO}    read cell data by name    ${sheetName}    C${row}
        ${backPcapfile}    read cell data by name    ${sheetName}    D${row}
        ${savePcapfileFlag}    read cell data by name    ${sheetName}    E${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    F${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    G${row}
        ${expectTotalNum}    read cell data by name    ${sheetName}    H${row}
        comment    下发业务配置
        ${expectTotalNum}    Run Keyword If    "${expectTotalNum}" != ""    evaluate    ${expectTotalNum}*${ingroup_member_num}
        New Connection Custom
        ${ruleSuf}=    Run Keyword If    "stage" in "${rulePre}" or "grouped" in "${rulePre}"    Set Variable    action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true total_limit_num ${expectTotalNum}m
        ...    ELSE    Set Variable    ${EMPTY}
        #    ${acl_all}    catenate    ${rulePre}    ${ruleSuf}
        ${acl_all}    Run Keyword If    "group_a" in "${rulePre}" or "group_b" in "${rulePre}" \ \ and \ "grouped_rule" not in "${rulePre}"    Replace String    ${rulePre}    temp    action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true
        ...    ELSE    catenate    ${rulePre}    ${ruleSuf}
        telnet.write    ${acl_all}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    should not contain    ${info}    ERROR
        ${totalAcl}    Set Variable    ${${totalAcl}+1}
        Append To List    ${totalAppIdList}    ${appId}
        Continue For Loop If    '${pcapfileOrNO}' == 'no'
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_back    ${backPcapfile}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${totalAppIdList}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit    ${pcapfileOrNO}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword If    '${expectTotalNum}' !='0'    getAclHitstatistics    ${totalAppIdList}
        ...    ELSE    Set Variable    1
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${hitCount}    ${0}    业务流的hitCount等于0
        Comment    通过hash校验包的完整性
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${pcapfileOrNO}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    ${savePcapfileFlag}_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Run Keyword If    ${rx} !=0    Should Be True    ${hashResult}
        checkNumOrTimeResult    ${savePcapfileFlag}_${row}_hit.pcap    ${expectTotalNum}    0    ${startFlowSpeed}    1    ${wuCha}
        Comment    删除本次循环时下发的acl，进入下一次循环acl下发
        ${totalAcl}    Set Variable    0
        ${totalAppIdList}    Create List
        New Connection Custom
        telnet.write    show acl all | include "grouped_rule"
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${info}    forward    阻断后，CLI下查询到规则未删除
    END
