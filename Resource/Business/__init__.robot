*** Keywords ***
indirect_copy_not_specified
    ${device_id}    Set Variable    0000000
    ${server_out_flag}    Set Variable    00000010
    ${server7_aclgroupid}    Set Variable    00000000
    ${server6_aclgroupid}    Set Variable    00000000
    ${server5_aclgroupid}    Set Variable    00000000
    ${server4_aclgroupid}    Set Variable    00000000
    ${server3_aclgroupid}    Set Variable    00000000
    ${server2_aclgroupid}    Set Variable    00000000
    ${server1_aclgroupid}    Set Variable    00000000
    ${server0_aclgroupid}    Set Variable    00000001
    ${inport_direct}    Set Variable    0    #暂时默认0
    ${inportid}    Set Variable    000000000000    #输入端口
    RETURN    ${device_id}    ${server_out_flag}    ${server7_aclgroupid}    ${server6_aclgroupid}    ${server5_aclgroupid}    ${server4_aclgroupid}    ${server3_aclgroupid}    ${server2_aclgroupid}    ${server1_aclgroupid}    ${server0_aclgroupid}    ${inport_direct}    ${inportid}

direct_copy
    ${device_id}    Set Variable    0000000
    ${server_out_flag}    Set Variable    00000001
    ${server7_aclgroupid}    Set Variable    00000000
    ${server6_aclgroupid}    Set Variable    00000000
    ${server5_aclgroupid}    Set Variable    00000000
    ${server4_aclgroupid}    Set Variable    00000000
    ${server3_aclgroupid}    Set Variable    00000000
    ${server2_aclgroupid}    Set Variable    00000000
    ${server1_aclgroupid}    Set Variable    00000000
    ${server0_aclgroupid}    Set Variable    00000001
    ${inport_direct}    Set Variable    0
    ${inportid}    Set Variable    000000000000
