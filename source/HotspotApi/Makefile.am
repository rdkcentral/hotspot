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
lib_LTLIBRARIES = libHotspotApi.la

AM_CFLAGS = -I$(top_srcdir)/source
AM_CFLAGS += -I$(top_srcdir)/source/include
AM_CFLAGS += -I$(top_srcdir)/source/util
AM_CFLAGS += -DWBCFG_MULTI_COMP_SUPPORT

AM_LDFLAGS = -lpthread -lz -lsysevent -lsyscfg -lulog -llmapi -lnetfilter_queue -lnfnetlink -lccsp_common -ltelemetry_msgsender -ljansson

libHotspotApi_la_SOURCES = libHotspot.h libHotspotApi.h HotspotApi.c HotspotLib.c HotspotJansson.c
libHotspotApi_la_LDFLAGS = -ljansson -lsyscfg
if CORE_NET_LIB_FEATURE_SUPPORT
libHotspotApi_la_LDFLAGS += -lnet
endif
