##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
bin_PROGRAMS = CcspHotspot

AM_CFLAGS = -I$(top_srcdir)/source
AM_CFLAGS += -I$(top_srcdir)/source/include
AM_CFLAGS += -I$(top_srcdir)/source/util
AM_CFLAGS += -I$(top_srcdir)/source/hotspotfd/include
AM_CFLAGS += -I$(top_srcdir)/source/HotspotApi

AM_LDFLAGS = -lpthread -lz -lsysevent -lsyscfg -lulog -llmapi -lnetfilter_queue -lnfnetlink -lccsp_common -ltelemetry_msgsender -lsecure_wrapper -lprivilege

CcspHotspot_SOURCES = hotspotfd.c dhcpsnooper.c ssp_messagebus_interface.c ssp_main.c ssp_action.c cosa_hotspot_dml.c plugin_main.c dm_pack_datamodel.c

if FEATURE_WAN_FAIL_OVER
AM_CFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus
AM_CFLAGS += -DWAN_FAILOVER_SUPPORTED
AM_LDFLAGS += -lrbus
endif
CcspHotspot_LDADD = ${top_builddir}/source/HotspotApi/libHotspotApi.la
