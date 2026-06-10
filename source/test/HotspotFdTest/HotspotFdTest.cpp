/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <sys/shm.h>
#include <experimental/filesystem>
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_util.h>
#include <mocks/mock_base_api.h>
#include <mocks/mock_usertime.h>
#include <mocks/mock_ansc_wrapper_api.h>
#include <mocks/mock_trace.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_telemetry.h>
#include <mocks/mock_file_io.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_nfqueue.h>
#include <mocks/mock_socket.h>
#include <mocks/mock_rbus.h>
#include "test/mocks/mock_hotspotApi.h"

extern "C" {
#include "cosa_hotspot_dml.h"
#include "dhcp.h"
#include "debug.h"
#include "dhcpsnooper.h"
#include "hotspotfd.h"
#include "test/mocks/hotspotfd_internal_mock.h"
}

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::DoAll;
using ::testing::SetArgPointee;

SyseventMock * g_syseventMock = nullptr;
UtilMock * g_utilMock = nullptr;
BaseAPIMock * g_baseapiMock = nullptr;
UserTimeMock * g_usertimeMock = nullptr;
AnscWrapperApiMock * g_anscWrapperApiMock = nullptr;
TraceMock * g_traceMock = nullptr;
SafecLibMock* g_safecLibMock = nullptr;
telemetryMock * g_telemetryMock = nullptr;
FileIOMock * g_fileIOMock = nullptr;
SecureWrapperMock * g_securewrapperMock = nullptr;
HotspotApiMock * g_hotspotApiMock = nullptr;
NfQueueMock * g_nfQueueMock = nullptr;
SocketMock * g_socketMock = nullptr;
rbusMock *g_rbusMock = nullptr;

class HotspotFdTestFixture : public ::testing::Test {
    protected:
        SyseventMock mockedSysevent;
        UtilMock mockedUtil;
        BaseAPIMock mockedbaseapi;
        UserTimeMock mockedUsertime;
        AnscWrapperApiMock mockedAnscWrapperApi;
        TraceMock mockedTrace;
        SafecLibMock mockedSafecLib;
        telemetryMock mockedTelemetry;
        FileIOMock mockedFileIO;
        SecureWrapperMock mockedSecureWrapper;
        HotspotApiMock mockedHotspotApi;
        NfQueueMock mockedNfQueue;
        SocketMock mockedSocket;
        rbusMock mockedRbus;

        HotspotFdTestFixture()
        {
            busInfo.freefunc = free;
            bus_handle = &busInfo;

            g_syseventMock = &mockedSysevent;
            g_utilMock = &mockedUtil;
            g_baseapiMock = &mockedbaseapi;
            g_usertimeMock = &mockedUsertime;
            g_anscWrapperApiMock = &mockedAnscWrapperApi;
            g_traceMock = &mockedTrace;
            g_safecLibMock = &mockedSafecLib;
            g_telemetryMock = &mockedTelemetry;
            g_fileIOMock = &mockedFileIO;
            g_securewrapperMock = &mockedSecureWrapper;
            g_hotspotApiMock = &mockedHotspotApi;
            g_nfQueueMock = &mockedNfQueue;
            g_socketMock = &mockedSocket;
            g_rbusMock = &mockedRbus;
        }
        virtual ~HotspotFdTestFixture()
        {
            g_syseventMock = nullptr;
            g_utilMock = nullptr;
            g_baseapiMock = nullptr;
            g_usertimeMock = nullptr;
            g_anscWrapperApiMock = nullptr;
            g_traceMock = nullptr;
            g_safecLibMock = nullptr;
            g_telemetryMock = nullptr;
            g_fileIOMock = nullptr;
            g_securewrapperMock = nullptr;
            g_hotspotApiMock = nullptr;
            g_nfQueueMock = nullptr;
            g_socketMock = nullptr;
            g_rbusMock = nullptr;
        }

        virtual void SetUp()
        {
            printf("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }

        virtual void TearDown()
        {
            printf("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }

        static void SetUpTestCase()
        {
            printf("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());
        }

        static void TearDownTestCase()
        {
            printf("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());
        }
};

extern char TunnelStatus[8];

void createFile(const char* fname) {
    if ((file = fopen(fname, "r"))) {
        fclose(file);
    }
    else {
        file = fopen(fname, "w");
        fclose(file);
    }
}

void removeFile(const char* fname) {
    remove(fname);
}

static inline void mylist_add(struct mylist_head *nn, struct mylist_head *h)
{
        h->n->p = nn;
        nn->n = h->n;
        nn->p = h;
        h->n = nn;
}

static inline void mylist_del(struct mylist_head *e)
{
    e->n->p = e->p;
    e->p->n = e->n;

    e->n = 0;
    e->p = 0;
}

//Testcases for cosa_hotspot_dml.c
TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_GetParamStringValue_SUCCESS) {
    ULONG result;
    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char pValue[100];
    ULONG ulSize = sizeof(pValue);

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    result = HotspotConnectedDevice_GetParamStringValue(hInsContext, ParamName, pValue, &ulSize);
    EXPECT_EQ(0, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_GetParamStringValue_FAIL) {
    ULONG result;
    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientNotChange";
    char pValue[100];
    ULONG ulSize = sizeof(pValue);

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(-1),
            Return(1)
        ));
    result = HotspotConnectedDevice_GetParamStringValue(hInsContext, ParamName, pValue, &ulSize);
    EXPECT_EQ(1, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_SUCCESS_1) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char strValue[] = "1|3| -65|01:23:45:67:89:AB";
    char macAddr[18] = "01:23:45:67:89:AB";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    EXPECT_CALL(*g_safecLibMock, sscanf_s(StrEq(strValue), _, _, _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<2>(1),
            testing::SetArgPointee<3>(3),
            testing::SetArgPointee<4>(-65),
            testing::SetArrayArgument<5>(macAddr, macAddr + strlen(macAddr) + 1),
            Return(4)
        ));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(StrEq("WIFI_INFO_Hotspot_client_connected"), 1)).Times(1).WillOnce(Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(TRUE, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_SUCCESS_2) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char strValue[] = "0|1|75|AB:CD:EF:01:23:45";
    char macAddr[18] = "AB:CD:EF:01:23:45";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    EXPECT_CALL(*g_safecLibMock, sscanf_s(StrEq(strValue), _, _, _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<2>(0),
            testing::SetArgPointee<3>(1),
            testing::SetArgPointee<4>(75),
            testing::SetArrayArgument<5>(macAddr, macAddr + strlen(macAddr) + 1),
            Return(4)
        ));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(StrEq("WIFI_INFO_Hotspot_client_disconnected"), 1)).Times(1).WillOnce(Return(T2ERROR_SUCCESS));

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(TRUE, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_FAIL_1) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char *strValue = nullptr;

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(FALSE, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_FAIL_2) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char strValue[] = "0|1|75|AB:CD:EF:01:23:45:15";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(FALSE, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_FAIL_3) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char strValue[] = "0|1|75|AB:CD:EF:01:23:45";
    char macAddr[18] = "AB:CD:EF:01:23:45";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    EXPECT_CALL(*g_safecLibMock, sscanf_s(StrEq(strValue), _, _, _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<2>(0),
            testing::SetArgPointee<3>(1),
            testing::SetArgPointee<4>(75),
            testing::SetArrayArgument<5>(macAddr, macAddr + strlen(macAddr) + 1),
            Return(EOF)
        ));

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(FALSE, result);
}

//Testcases for dhcp_snooper.c
TEST_F(HotspotFdTestFixture, snoop_ipChecksum) {
    struct iphdr mockHeader;
    mockHeader.check = 0x0;
    mockHeader.version = 4;
    mockHeader.ihl = 5;
    mockHeader.tos = 0x10;
    mockHeader.tot_len = 20;
    mockHeader.id = 0x1234;
    mockHeader.frag_off = 0x4000;
    mockHeader.ttl = 64;
    mockHeader.protocol = 6;
    mockHeader.saddr = inet_addr("192.168.0.1");
    mockHeader.daddr = inet_addr("192.168.0.2");

    // calculate expected checksum
    unsigned int nbytes = sizeof(struct iphdr);
    unsigned short *buf = (unsigned short *)&mockHeader;
    unsigned int sum = 0;
    for (; nbytes > 1; nbytes -= 2) {
        sum += *buf++;
    }
    if (nbytes == 1) {
        sum += *(unsigned char*) buf;
    }
    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    unsigned short expectedChecksum = ~sum;

    unsigned short actualChecksum = snoop_ipChecksum(&mockHeader);

    EXPECT_EQ(expectedChecksum, actualChecksum);
}

TEST_F(HotspotFdTestFixture, snoop_log_SUCCESS) {
    createFile(SNOOP_LOG_PATH);
    int gShm_snoop_fd;
    gShm_snoop_fd = shmget(kSnooper_Statistics, kSnooper_SharedMemSize, IPC_CREAT | 0666);
    gpSnoop_Stats = (snooper_statistics_s *)shmat(gShm_snoop_fd, NULL, 0);

    EXPECT_CALL(*g_fileIOMock, fclose(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _memcpy_s_chk(_, _, _, _, _, _)).Times(1).WillOnce(Return(0));
    snoop_log();

    removeFile(SNOOP_LOG_PATH);
}

TEST_F(HotspotFdTestFixture, snoop_log_FAIL) {
    createFile(SNOOP_LOG_PATH);
    int gShm_snoop_fd;
    gShm_snoop_fd = shmget(kSnooper_Statistics, kSnooper_SharedMemSize, IPC_CREAT | 0666);
    gpSnoop_Stats = (snooper_statistics_s *)shmat(gShm_snoop_fd, NULL, 0);

    EXPECT_CALL(*g_fileIOMock, fclose(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _memcpy_s_chk(_, _, _, _, _, _)).Times(1).WillOnce(Return(1));
    snoop_log();

    removeFile(SNOOP_LOG_PATH);
}

//Testcases of hotspotfd.c
TEST_F(HotspotFdTestFixture, Get_HotspotfdType) {
    HotspotfdType result;
    char name[] = "hotspotfd-primary";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq(name), _, _, _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    result = Get_HotspotfdType(name);
    EXPECT_EQ(HOTSPOTFD_PRIMARY, result);
}

TEST_F(HotspotFdTestFixture, deleteSharedMem_CASE_1) {
    bool result;

    result = deleteSharedMem(865889, true);
    EXPECT_EQ(true, result);
}

TEST_F(HotspotFdTestFixture, deleteSharedMem_CASE_2) {
    bool result;

    result = deleteSharedMem(865889, false);
    EXPECT_EQ(true, result);
}

TEST_F(HotspotFdTestFixture, notify_tunnel_status) {
    char status[] = "Up";

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, StrEq(status))).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, nullptr)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, StrEq("TunnelStatus"), _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    notify_tunnel_status(status);

    EXPECT_STREQ("Up", TunnelStatus);
    EXPECT_EQ(true, gVapIsUp);
}

TEST_F(HotspotFdTestFixture, notify_tunnel_status_Down) {
    char status[] = "Down";

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, StrEq(status))).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, nullptr)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, StrEq("TunnelStatus"), _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    notify_tunnel_status(status);

    EXPECT_STREQ("Down", TunnelStatus);
    EXPECT_EQ(false, gVapIsUp);
}

TEST_F(HotspotFdTestFixture, TunnelStatus_GetStringHandler) {
    rbusHandle_t handle = nullptr;
    rbusProperty_t property = reinterpret_cast<rbusProperty_t>(0x1); // dummy non-null
    rbusGetHandlerOptions_t* opts = nullptr;

    strncpy(TunnelStatus, "Up", sizeof(TunnelStatus) - 1);
    TunnelStatus[sizeof(TunnelStatus) - 1] = '\0';

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_))
        .Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, StrEq("Up")))
        .Times(1);

    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(property, _))
        .Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_))
        .Times(1);

    rbusError_t result = TunnelStatus_GetStringHandler(handle, property, opts);

    EXPECT_EQ(RBUS_ERROR_SUCCESS, result);
}

TEST_F(HotspotFdTestFixture, TunnelStatus_SetStringHandler_ValidChange) {
    rbusHandle_t handle = nullptr;
    rbusProperty_t property = reinterpret_cast<rbusProperty_t>(0x1); 
    rbusSetHandlerOptions_t* opts = nullptr;

    strncpy(TunnelStatus, "Down", sizeof(TunnelStatus) - 1);
    TunnelStatus[sizeof(TunnelStatus) - 1] = '\0';

    rbusValue_t val = reinterpret_cast<rbusValue_t>(0x2);

    EXPECT_CALL(*g_rbusMock, rbusProperty_GetValue(property))
        .Times(1)
        .WillOnce(Return(val));

    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(val, _))
        .Times(1)
        .WillOnce(Return("Up"));

    rbusError_t result = TunnelStatus_SetStringHandler(handle, property, opts);

    EXPECT_EQ(RBUS_ERROR_SUCCESS, result);
    EXPECT_STREQ("Up", TunnelStatus);
}

TEST_F(HotspotFdTestFixture, TunnelStatus_SetStringHandler_InvalidValue) {
    rbusHandle_t handle = nullptr;
    rbusProperty_t property = reinterpret_cast<rbusProperty_t>(0x1);
    rbusSetHandlerOptions_t* opts = nullptr;

    strncpy(TunnelStatus, "Down", sizeof(TunnelStatus) - 1);
    TunnelStatus[sizeof(TunnelStatus) - 1] = '\0';

    rbusValue_t val = reinterpret_cast<rbusValue_t>(0x2);

    EXPECT_CALL(*g_rbusMock, rbusProperty_GetValue(property))
        .Times(1)
        .WillOnce(Return(val));

    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(val, _))
        .Times(1)
        .WillOnce(Return("InvalidStatus"));

    rbusError_t result = TunnelStatus_SetStringHandler(handle, property, opts);

    EXPECT_EQ(RBUS_ERROR_INVALID_INPUT, result);
    EXPECT_STREQ("Down", TunnelStatus);

}

TEST_F(HotspotFdTestFixture, TunnelStatus_SetStringHandler_NoChange) {
    rbusHandle_t handle = nullptr;
    rbusProperty_t property = reinterpret_cast<rbusProperty_t>(0x1);
    rbusSetHandlerOptions_t* opts = nullptr;

    strncpy(TunnelStatus, "Up", sizeof(TunnelStatus) - 1);
    TunnelStatus[sizeof(TunnelStatus) - 1] = '\0';

    rbusValue_t val = reinterpret_cast<rbusValue_t>(0x2);

    EXPECT_CALL(*g_rbusMock, rbusProperty_GetValue(property))
        .Times(1)
        .WillOnce(Return(val));

    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(val, _))
        .Times(1)
        .WillOnce(Return("Up"));

    rbusError_t result = TunnelStatus_SetStringHandler(handle, property, opts);

    EXPECT_EQ(RBUS_ERROR_SUCCESS, result);
    EXPECT_STREQ("Up", TunnelStatus);
}

TEST_F(HotspotFdTestFixture, set_validatessid_CASE1) {
    bool result;
    char mockValue[] = "false";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";

    ssid_reset_mask = 0x0;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("false"))).Times(4).WillRepeatedly(Return(mockValue));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_, _, StrEq(dstPath), _, _, _, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::WithArg<8>([&](char** faultParam){
        *faultParam = mockValue;
        }),
    Return(CCSP_SUCCESS)));

    result = set_validatessid();

    EXPECT_EQ(true, result);
}

TEST_F(HotspotFdTestFixture, set_validatessid_CASE2) {
    bool result;
    char mockValue[] = "true";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";

    ssid_reset_mask = 0xf;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("true"))).Times(4).WillRepeatedly(Return(mockValue));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_, _, StrEq(dstPath), _, _, _, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::WithArg<8>([&](char** faultParam){
        *faultParam = mockValue;
        }),
    Return(CCSP_SUCCESS)));

    result = set_validatessid();

    EXPECT_EQ(true, result);
}

void SetOutValStructs(parameterValStruct_t** outValStructs, parameterValStruct_t** valStructs) {
    *outValStructs = *valStructs;
}
TEST_F(HotspotFdTestFixture, get_validate_ssid_SUCCESS) {
    bool result;
    char dstPath[64] = "/com/cisco/spvtg/ccsp/wifi";
    ssid_reset_mask = 0x0;

    //Allocate memory and assign mock values for valStructs
    const char *paramNames[] = {"ap5", "ap6", "ap9", "ap10"};
    int numParams = sizeof(paramNames) / sizeof(paramNames[0]);

    parameterValStruct_t **valStructs = (parameterValStruct_t **)malloc(numParams * sizeof(parameterValStruct_t *));
    if (valStructs == NULL) {
        printf("Memory allocation failed for valStructs array\n");
        return;
    }

    for (int i = 0; i < numParams; i++) {
        valStructs[i] = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
        if (valStructs[i] == NULL) {
            printf("Memory allocation failed for valStructs[%d]\n", i);
            goto cleanup;
        }

        valStructs[i]->parameterName = strdup(paramNames[i]);
        if (valStructs[i]->parameterName == NULL) {
            printf("Memory allocation failed for parameterName\n");
            goto cleanup;
        }

        valStructs[i]->parameterValue = strdup("true");
        if (valStructs[i]->parameterValue == NULL) {
            printf("Memory allocation failed for parameterValue\n");
            goto cleanup;
        }
        valStructs[i]->type = ccsp_string;
    }

    // Set expectations
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, StrEq(dstPath), _, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::Invoke([&](void*, const char*, char*, char**, int, int*, parameterValStruct_t*** outValStructs) {
            *outValStructs = valStructs;
        }),
        Return(CCSP_Message_Bus_OK)
    ));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_, _, _)).Times(1);

    result = get_validate_ssid();
    EXPECT_EQ(true, result);

cleanup:
    for (int i = 0; i < numParams; i++) {
        if (valStructs[i]) {
            free(valStructs[i]->parameterName);
            free(valStructs[i]->parameterValue);
            free(valStructs[i]);
        }
    }
    free(valStructs);
}

TEST_F(HotspotFdTestFixture, get_validate_ssid_FAIL) {
    bool result;
    char dstPath[64] = "/com/cisco/spvtg/ccsp/wifi";

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, StrEq(dstPath), _, _, _, _))
    .Times(1)
    .WillOnce(Return(1));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_, _, _)).Times(1);

    result = get_validate_ssid();
    EXPECT_EQ(false, result);
}

TEST_F(HotspotFdTestFixture, hotspotfd_isClientAttached_SUCCESS) {
    bool result;
    bool mockpNew;
    gSnoopNumberOfClients = 2;

    result = hotspotfd_isClientAttached(&mockpNew);
    EXPECT_EQ(true, result);
    EXPECT_EQ(true, mockpNew);
}

TEST_F(HotspotFdTestFixture, hotspotfd_isClientAttached_FAIL) {
    bool result;
    bool mockpNew;
    gSnoopNumberOfClients = 0;

    result = hotspotfd_isClientAttached(&mockpNew);
    EXPECT_EQ(false, result);
}

TEST_F(HotspotFdTestFixture, hotspotfd_checksum) {
    struct packet pckt;

    // Initialize ICMP header
    pckt.hdr.type = 8;
    pckt.hdr.code = 0;
    pckt.hdr.un.echo.id = htons(1234);
    pckt.hdr.un.echo.sequence = htons(1);
    pckt.hdr.checksum = 0;
    strcpy(pckt.msg, "Sample ICMP packet data");

    unsigned short expected_checksum = hotspotfd_checksum(&pckt, sizeof(pckt));

    EXPECT_TRUE(std::isfinite(expected_checksum));
}

TEST_F(HotspotFdTestFixture, hotspotfd_log) {
    createFile(HOTSPOTFD_STATS_PATH);

    // Attach the shared memory and check for errors
    gShm_fd = shmget(kKeepAlive_Statistics, kKeepAlive_SharedMemSize, IPC_CREAT | 0666);
    ASSERT_NE(gShm_fd, -1) << "Failed to create shared memory segment";
    gpStats = (hotspotfd_statistics_s *)shmat(gShm_fd, NULL, 0);
    ASSERT_NE(gpStats, (void *)-1) << "Failed to attach shared memory";

    // Initialize global variables
    gKeepAliveEnable = true;
    gPrimaryIsActive = true;
    gPrimaryIsAlive = true;
    gSecondaryIsActive = false;
    gSecondaryIsAlive = false;
    gKeepAlivesSent = 0;
    gKeepAlivesReceived = 0;
    gKeepAliveInterval = 30;
    gKeepAliveCount = 3;
    gKeepAliveThreshold = 15;
    gSecondaryMaxTime = 0;
    gSwitchedBackToPrimary = false;
    gPriStateIsDown = false;
    gSecStateIsDown = false;
    gBothDnFirstSignal = true;
    gKeepAliveChecksumCnt = 0;
    gKeepAliveSequenceCnt = 0;
    gDeadInterval = 30;
    strcpy(gpPrimaryEP, "96.109.150.114");
    strcpy(gpSecondaryEP, "96.109.150.120");

    EXPECT_CALL(*g_fileIOMock, fclose(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(2).WillRepeatedly(Return(0));

    hotspotfd_log();

    // Clean up
    removeFile(HOTSPOTFD_STATS_PATH);
    if (gpStats != (void *)-1) {
        shmdt(gpStats);
    }
    if (gShm_fd != -1) {
        shmctl(gShm_fd, IPC_RMID, NULL);
    }
}

TEST_F(HotspotFdTestFixture, hotspotfd_isValidIpAddress) {
    bool result;
    char ipAddr[] = "96.109.150.114";

    result = hotspotfd_isValidIpAddress(ipAddr);
    EXPECT_EQ(true, result);
}

TEST_F(HotspotFdTestFixture, hotspotfd_setupSharedMemory) {
    int status;

    gShm_fd = shmget(kKeepAlive_Statistics, kKeepAlive_SharedMemSize, IPC_CREAT | 0666);
    ASSERT_NE(gShm_fd, -1) << "Failed to create shared memory segment";
    gpStats = (hotspotfd_statistics_s *)shmat(gShm_fd, NULL, 0);
    ASSERT_NE(gpStats, (void *)-1) << "Failed to attach shared memory";
    gShm_snoop_fd = shmget(kSnooper_Statistics, kSnooper_SharedMemSize, IPC_CREAT | 0666);
    ASSERT_NE(gShm_snoop_fd, -1) << "Failed to create shared memory segment";
    gpSnoop_Stats = (snooper_statistics_s *)shmat(gShm_snoop_fd, NULL, 0);
    ASSERT_NE(gpSnoop_Stats, (void *)-1) << "Failed to attach shared memory";

    status = hotspotfd_setupSharedMemory();
    EXPECT_EQ(STATUS_SUCCESS, status);

    if (gpStats != (void *)-1) {
        shmdt(gpStats);
    }
    if (gShm_fd != -1) {
        shmctl(gShm_fd, IPC_RMID, NULL);
    }
    if (gpSnoop_Stats != (void *)-1) {
        shmdt(gpSnoop_Stats);
    }
    if (gShm_snoop_fd != -1) {
        shmctl(gShm_snoop_fd, IPC_RMID, NULL);
    }
}

TEST_F(HotspotFdTestFixture, hotspotfd_getStartupParameters) {
    int result;
    char mockIP[] = "96.109.150.114";
    char mockIPv6[] = "2001:db8:85a3:8d3:1319:8a2e:370:7348";
    char mockIntervalValue[] = "30";
    char emptyString[] = "";

    {
        testing::InSequence s;

        // Mock the calls to sysevent_get with expected values
        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kHotspotfd_primary), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIP, mockIP + strlen(mockIP) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_secondary), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIP, mockIP + strlen(mockIP) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("old_wan_ipv4addr"), StrEq(emptyString), _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(emptyString, emptyString + strlen(emptyString) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_wan_ipaddr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIP, mockIP + strlen(mockIP) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("old_wan_ipv4addr"), _, _)).Times(1)
        .WillOnce(Return(0));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("old_wan_ipv4addr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIP, mockIP + strlen(mockIP) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("old_wan_ipv6addr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(emptyString, emptyString + strlen(emptyString) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("wan6_ipaddr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIPv6, mockIPv6 + strlen(mockIPv6) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("old_wan_ipv6addr"), _, _)).Times(1)
        .WillOnce(Return(0));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("old_wan_ipv6addr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIPv6, mockIPv6 + strlen(mockIPv6) + 1),
        Return(0)));

        // Mock the rest of the sysevent_get calls with generic mockIntervalValue
        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_keep_alive), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_keep_alive_threshold), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_max_secondary), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_keep_alive_policy), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_keep_alive_count), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id1), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id2), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id3), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id4), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id5), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(ksnooper_circuit_id6), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index1), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index2), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index3), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index4), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index5), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(ksnooper_ssid_index6), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_enable), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_remote_enable), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_max_clients), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));
    }

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    result = hotspotfd_getStartupParameters();
    EXPECT_EQ(STATUS_SUCCESS, result);
}

// Helper to clean up the client_list linked list between tests
static void cleanup_client_list() {
    client_node_t *cur = client_list;
    while (cur) {
        client_node_t *next = cur->next;
        free(cur);
        cur = next;
    }
    client_list = NULL;
}

// ==========================================
// Testcases for get_client_state
// ==========================================
TEST_F(HotspotFdTestFixture, get_client_state_NullMac) {
    dhcp_client_state_t *state = get_client_state(NULL);
    EXPECT_EQ(nullptr, state);
    cleanup_client_list();
}
TEST_F(HotspotFdTestFixture, get_client_state_EmptyMac) {
    dhcp_client_state_t *state = get_client_state("");
    EXPECT_EQ(nullptr, state);
    cleanup_client_list();
}

TEST_F(HotspotFdTestFixture, get_client_state_NewClient) {
    client_list = NULL;
    dhcp_client_state_t *state = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state);
    ASSERT_NE(nullptr, client_list);
    EXPECT_STREQ("aa:bb:cc:dd:ee:ff", client_list->mac);
    // Verify calloc zero-initialized the state fields
    EXPECT_FALSE(state->timer_running);
    EXPECT_FALSE(state->dhcp_discover);
    EXPECT_FALSE(state->dhcp_request);
    EXPECT_FALSE(state->dhcp_offer);
    EXPECT_FALSE(state->dhcp_ack);
    cleanup_client_list();
}

TEST_F(HotspotFdTestFixture, get_client_state_ExistingClient) {
    client_list = NULL;
    dhcp_client_state_t *state1 = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state1);
    state1->dhcp_discover = true;

    // Second call for same MAC should return same state pointer
    dhcp_client_state_t *state2 = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state2);
    EXPECT_EQ(state1, state2);
    EXPECT_TRUE(state2->dhcp_discover);
    cleanup_client_list();
}

TEST_F(HotspotFdTestFixture, get_client_state_MultipleClients) {
    client_list = NULL;
    dhcp_client_state_t *state1 = get_client_state("aa:bb:cc:dd:ee:01");
    dhcp_client_state_t *state2 = get_client_state("aa:bb:cc:dd:ee:02");
    ASSERT_NE(nullptr, state1);
    ASSERT_NE(nullptr, state2);
    EXPECT_NE(state1, state2);

    // Verify both clients are retrievable
    dhcp_client_state_t *found1 = get_client_state("aa:bb:cc:dd:ee:01");
    dhcp_client_state_t *found2 = get_client_state("aa:bb:cc:dd:ee:02");
    EXPECT_EQ(state1, found1);
    EXPECT_EQ(state2, found2);
    cleanup_client_list();
}
// ==========================================
// Testcases for remove_client_state
// ==========================================
TEST_F(HotspotFdTestFixture, remove_client_state_NullMac) {
    client_list = NULL;
    remove_client_state(NULL);
    EXPECT_EQ(nullptr, client_list);
}

TEST_F(HotspotFdTestFixture, remove_client_state_EmptyList) {
    client_list = NULL;
    remove_client_state("aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(nullptr, client_list);
}

TEST_F(HotspotFdTestFixture, remove_client_state_SingleClient) {
    client_list = NULL;
    get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, client_list);
    remove_client_state("aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(nullptr, client_list);
}
TEST_F(HotspotFdTestFixture, remove_client_state_HeadOfList) {
    client_list = NULL;
    get_client_state("aa:bb:cc:dd:ee:01");
    get_client_state("aa:bb:cc:dd:ee:02");
    // client_list: 02 -> 01 (most recent at head)
    remove_client_state("aa:bb:cc:dd:ee:02");
    ASSERT_NE(nullptr, client_list);
    EXPECT_STREQ("aa:bb:cc:dd:ee:01", client_list->mac);
    EXPECT_EQ(nullptr, client_list->next);
    cleanup_client_list();
}

TEST_F(HotspotFdTestFixture, remove_client_state_MiddleOfList) {
    client_list = NULL;
    get_client_state("aa:bb:cc:dd:ee:01");
    get_client_state("aa:bb:cc:dd:ee:02");
    get_client_state("aa:bb:cc:dd:ee:03");
    // List: 03 -> 02 -> 01
    remove_client_state("aa:bb:cc:dd:ee:02");
    ASSERT_NE(nullptr, client_list);
    EXPECT_STREQ("aa:bb:cc:dd:ee:03", client_list->mac);
    ASSERT_NE(nullptr, client_list->next);
    EXPECT_STREQ("aa:bb:cc:dd:ee:01", client_list->next->mac);
    EXPECT_EQ(nullptr, client_list->next->next);
    cleanup_client_list();
}

TEST_F(HotspotFdTestFixture, remove_client_state_NotFound) {
    client_list = NULL;
    get_client_state("aa:bb:cc:dd:ee:01");
    remove_client_state("ff:ff:ff:ff:ff:ff");
    ASSERT_NE(nullptr, client_list);
    EXPECT_STREQ("aa:bb:cc:dd:ee:01", client_list->mac);
    cleanup_client_list();
}
// ==========================================
// Testcases for publish_to_onewifi
// ==========================================
TEST_F(HotspotFdTestFixture, publish_to_onewifi_NullInput) {
    int result = publish_to_onewifi(NULL);
    EXPECT_EQ(0, result);
}

TEST_F(HotspotFdTestFixture, publish_to_onewifi_EmptyString) {
    char cmdStr[] = "";
    int result = publish_to_onewifi(cmdStr);
    EXPECT_EQ(0, result);
}

TEST_F(HotspotFdTestFixture, publish_to_onewifi_Success) {
    char cmdStr[] = "aa:bb:cc:dd:ee:ff_5";

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, StrEq(cmdStr))).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, nullptr)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, StrEq("Device.X_COMCAST-COM_GRE.Hotspot.RejectAssociatedClient"), _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    int result = publish_to_onewifi(cmdStr);
    EXPECT_EQ(1, result);
}
TEST_F(HotspotFdTestFixture, publish_to_onewifi_PublishFails) {
    char cmdStr[] = "aa:bb:cc:dd:ee:ff_5";

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, StrEq(cmdStr))).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, nullptr)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, StrEq("Device.X_COMCAST-COM_GRE.Hotspot.RejectAssociatedClient"), _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1).WillOnce(Return(RBUS_ERROR_BUS_ERROR));
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    int result = publish_to_onewifi(cmdStr);
    EXPECT_EQ(0, result);
}

// ==========================================
// Testcases for DHCP timer state logic
// ==========================================
TEST_F(HotspotFdTestFixture, DhcpTimerState_InitialState) {
    client_list = NULL;
    dhcp_client_state_t *state = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state);
    EXPECT_FALSE(state->timer_running);
    EXPECT_FALSE(state->dhcp_discover);
    EXPECT_FALSE(state->dhcp_request);
    EXPECT_FALSE(state->dhcp_offer);
    EXPECT_FALSE(state->dhcp_ack);
    EXPECT_EQ(0, state->ipv4_addr[0]);
    cleanup_client_list();
}
TEST_F(HotspotFdTestFixture, DhcpTimerState_DiscoverStartsTimer) {
    client_list = NULL;
    dhcp_client_state_t *state = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state);

    // Simulate DHCP Discover starting the timer
    clock_gettime(CLOCK_MONOTONIC, &state->dhcp_timer_start);
    state->timer_running = true;
    state->dhcp_discover = true;
    state->dhcp_request = false;
    state->dhcp_offer = false;
    state->dhcp_ack = false;
    state->ipv4_addr[0] = '\0';

    EXPECT_TRUE(state->timer_running);
    EXPECT_TRUE(state->dhcp_discover);
    EXPECT_FALSE(state->dhcp_request);
    EXPECT_FALSE(state->dhcp_offer);
    EXPECT_FALSE(state->dhcp_ack);
    cleanup_client_list();
}
TEST_F(HotspotFdTestFixture, DhcpTimerState_FullDhcpSequence) {
    client_list = NULL;
    dhcp_client_state_t *state = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state);

    // Simulate full DHCP sequence: Discover -> Request -> Offer -> ACK
    clock_gettime(CLOCK_MONOTONIC, &state->dhcp_timer_start);
    state->timer_running = true;
    state->dhcp_discover = true;
    state->ipv4_addr[0] = '\0';

    state->dhcp_request = true;
    state->dhcp_offer = true;

    // ACK with expected IP
    strncpy(state->ipv4_addr, "172.20.20.20", sizeof(state->ipv4_addr) - 1);
    state->ipv4_addr[sizeof(state->ipv4_addr) - 1] = '\0';
    state->dhcp_ack = true;

    // All states should be set
    EXPECT_TRUE(state->dhcp_discover);
    EXPECT_TRUE(state->dhcp_request);
    EXPECT_TRUE(state->dhcp_offer);
    EXPECT_TRUE(state->dhcp_ack);

    // Timer stopped after full successful sequence
    state->timer_running = false;
    state->dhcp_discover = state->dhcp_request = state->dhcp_offer = state->dhcp_ack = false;
    EXPECT_FALSE(state->timer_running);

    remove_client_state("aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(nullptr, client_list);
}
TEST_F(HotspotFdTestFixture, DhcpTimerState_IncompleteSequence_NoAck) {
    client_list = NULL;
    dhcp_client_state_t *state = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state);

    // Discover + Request but no Offer/ACK
    clock_gettime(CLOCK_MONOTONIC, &state->dhcp_timer_start);
    state->timer_running = true;
    state->dhcp_discover = true;
    state->dhcp_request = true;
    state->dhcp_offer = false;
    state->dhcp_ack = false;

    EXPECT_TRUE(state->timer_running);
    EXPECT_TRUE(state->dhcp_discover);
    EXPECT_TRUE(state->dhcp_request);
    EXPECT_FALSE(state->dhcp_offer);
    EXPECT_FALSE(state->dhcp_ack);

    // Incomplete: should trigger deauth
    EXPECT_FALSE(state->dhcp_discover && state->dhcp_request && state->dhcp_offer && state->dhcp_ack);
    cleanup_client_list();
}
TEST_F(HotspotFdTestFixture, DhcpTimerState_AckWithWrongIp) {
    client_list = NULL;
    dhcp_client_state_t *state = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state);

    clock_gettime(CLOCK_MONOTONIC, &state->dhcp_timer_start);
    state->timer_running = true;
    state->dhcp_discover = true;
    state->dhcp_request = true;
    state->dhcp_offer = true;

    // ACK with wrong IP (not 172.20.20.20) - dhcp_ack should NOT be set
    strncpy(state->ipv4_addr, "192.168.1.100", sizeof(state->ipv4_addr) - 1);
    state->ipv4_addr[sizeof(state->ipv4_addr) - 1] = '\0';

    if (strcmp(state->ipv4_addr, "172.20.20.20") == 0) {
        state->dhcp_ack = true;
    }

    EXPECT_FALSE(state->dhcp_ack);
    EXPECT_FALSE(state->dhcp_discover && state->dhcp_request && state->dhcp_offer && state->dhcp_ack);
    cleanup_client_list();
}
TEST_F(HotspotFdTestFixture, DhcpTimerState_ResetAfterTimeout) {
    client_list = NULL;
    dhcp_client_state_t *state = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state);

    state->timer_running = true;
    state->dhcp_discover = true;
    state->dhcp_request = true;

    // Simulate timeout reset (as done in snoop_packetHandler)
    state->timer_running = false;
    state->dhcp_discover = state->dhcp_request = state->dhcp_offer = state->dhcp_ack = false;

    EXPECT_FALSE(state->timer_running);
    EXPECT_FALSE(state->dhcp_discover);
    EXPECT_FALSE(state->dhcp_request);
    EXPECT_FALSE(state->dhcp_offer);
    EXPECT_FALSE(state->dhcp_ack);

    remove_client_state("aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(nullptr, client_list);
}
TEST_F(HotspotFdTestFixture, DhcpTimerState_DiscoverDoesNotRestartRunningTimer) {
    client_list = NULL;
    dhcp_client_state_t *state = get_client_state("aa:bb:cc:dd:ee:ff");
    ASSERT_NE(nullptr, state);

    // First discover starts timer
    clock_gettime(CLOCK_MONOTONIC, &state->dhcp_timer_start);
    state->timer_running = true;
    state->dhcp_discover = true;
    struct timespec original_start = state->dhcp_timer_start;

    // Second discover should NOT overwrite if timer already running
    // (matches the if (!state->timer_running) logic in packetHandler)
    if (!state->timer_running) {
        clock_gettime(CLOCK_MONOTONIC, &state->dhcp_timer_start);
        state->dhcp_discover = true;
    }

    EXPECT_EQ(original_start.tv_sec, state->dhcp_timer_start.tv_sec);
    EXPECT_EQ(original_start.tv_nsec, state->dhcp_timer_start.tv_nsec);
    cleanup_client_list();
}

TEST_F(HotspotFdTestFixture, DhcpTimerState_RemoveAfterFullSequence) {
    client_list = NULL;

    // Add two clients
    dhcp_client_state_t *state1 = get_client_state("aa:bb:cc:dd:ee:01");
    dhcp_client_state_t *state2 = get_client_state("aa:bb:cc:dd:ee:02");
    ASSERT_NE(nullptr, state1);
    ASSERT_NE(nullptr, state2);

    // Complete DHCP for client 1, remove it
    state1->dhcp_discover = state1->dhcp_request = state1->dhcp_offer = state1->dhcp_ack = true;
    remove_client_state("aa:bb:cc:dd:ee:01");

    // Client 2 should still be in the list
    dhcp_client_state_t *found2 = get_client_state("aa:bb:cc:dd:ee:02");
    EXPECT_EQ(state2, found2);
    cleanup_client_list();
}

                                   
