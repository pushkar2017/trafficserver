# Makefile.am for Http
#
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

include $(top_srcdir)/build/tidy.mk

AM_CPPFLAGS += \
	$(iocore_include_dirs) \
	-I$(abs_top_srcdir)/proxy \
	-I$(abs_top_srcdir)/lib \
	-I$(abs_top_srcdir)/lib/records \
	-I$(abs_top_srcdir)/mgmt \
	-I$(abs_top_srcdir)/mgmt/utils \
	-I$(abs_top_srcdir)/proxy/hdrs \
	-I$(abs_top_srcdir)/proxy/shared \
	-I$(abs_top_srcdir)/proxy/logging \
	-I$(abs_top_srcdir)/proxy/http \
	$(TS_INCLUDES)

#noinst_HEADERS = HttpProxyServerMain.h
noinst_LIBRARIES = libtunnel.a

libtunnel_a_SOURCES = \
	Tunnel1ClientSession.cc \
	Tunnel1ClientSession.h \
	TunnelServerSession.cc \
	TunnelServerSession.h \
	TunnelDebugNames.cc \
	TunnelDebugNames.h

#if BUILD_TESTS
#libtunnel_a_SOURCES += HttpUpdateTester.cc \
#	RegressionHttpTransact.cc
#endif

check_PROGRAMS = \
test_ForwardedConfig

TESTS = $(check_PROGRAMS)

#test_ForwardedConfig_CPPFLAGS = $(AM_CPPFLAGS)\
#	-I$(abs_top_srcdir)/tests/include
#
#test_ForwardedConfig_SOURCES = \
#	unit-tests/test_ForwardedConfig.cc \
#	ForwardedConfig.cc \
#	unit-tests/test_ForwardedConfig_mocks.cc
#
#test_ForwardedConfig_LDADD = \
#	$(top_builddir)/lib/ts/libtsutil.la
#
clang-tidy-local: $(libtunnel_a_SOURCES) $(noinst_HEADERS)
	$(CXX_Clang_Tidy)

#test_UNUSED_SOURCES = \
#  TestHttpTransact.cc \
#  TestUrl.cc \
#  test_socket_close.cc \
#  testheaders.cc
