/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

/****************************************************************************

   L4RServerSession.h

   Description:


 ****************************************************************************/

#pragma once
/* Enable LAZY_BUF_ALLOC to delay allocation of buffers until they
 * are actually required.
 * Enabling LAZY_BUF_ALLOC, stop Http code from allocation space
 * for header buffer and tunnel buffer. The allocation is done by
 * the net code in read_from_net when data is actually written into
 * the buffer. By allocating memory only when it is required we can
 * reduce the memory consumed by TS process.
 *
 * IMPORTANT NOTE: enable/disable LAZY_BUF_ALLOC in HttpSM.h as well.
 */
#define LAZY_BUF_ALLOC

#include "P_Net.h"

//#include "HttpConnectionCount.h"
#include "HttpProxyAPIEnums.h"

//class HttpSM;
class MIOBuffer;
class IOBufferReader;

enum {
  L4R_SS_MAGIC_ALIVE = 0x0123FEED,
  L4R_SS_MAGIC_DEAD  = 0xDEADFEED,
};

enum LSS_State {
  LSS_INIT,
  LSS_ACTIVE,
  LSS_KA_CLIENT_SLAVE,
  LSS_KA_SHARED,
};

#if 0
enum {
  HTTP_SS_MAGIC_ALIVE = 0x0123FEED,
  HTTP_SS_MAGIC_DEAD  = 0xDEADFEED,
};
#endif

class L4RServerSession : public VConnection
{
public:
  L4RServerSession()
    : VConnection(nullptr),
      hostname_hash(),
      con_id(0),
      transact_count(0),
      state(LSS_INIT),
      server_trans_stat(0),
      private_session(false),
      sharing_match(TS_SERVER_SESSION_SHARING_MATCH_BOTH),
      sharing_pool(TS_SERVER_SESSION_SHARING_POOL_GLOBAL),
      enable_origin_connection_limiting(false),
      //connection_count(nullptr),
      read_buffer(nullptr),
      server_vc(nullptr),
      magic(L4R_SS_MAGIC_DEAD),
      buf_reader(nullptr)
  {
  }

  void destroy();
  void new_connection(NetVConnection *new_vc);

  void
  reset_read_buffer(void)
  {
    ink_assert(read_buffer->_writer);
    ink_assert(buf_reader != nullptr);
    read_buffer->dealloc_all_readers();
    read_buffer->_writer = nullptr;
    buf_reader           = read_buffer->alloc_reader();
  }

  IOBufferReader *
  get_reader()
  {
    return buf_reader;
  };

  VIO *do_io_read(Continuation *c, int64_t nbytes = INT64_MAX, MIOBuffer *buf = nullptr) override;

  VIO *do_io_write(Continuation *c = nullptr, int64_t nbytes = INT64_MAX, IOBufferReader *buf = nullptr,
                   bool owner = false) override;

  void do_io_close(int lerrno = -1) override;
  void do_io_shutdown(ShutdownHowTo_t howto) override;

  void reenable(VIO *vio) override;

  void release();
  void attach_hostname(const char *hostname);
  NetVConnection *
  get_netvc() const
  {
    return server_vc;
  };
  void
  set_netvc(NetVConnection *new_vc)
  {
    server_vc = new_vc;
  }

  // Keys for matching hostnames
  IpEndpoint const &
  get_server_ip() const
  {
    ink_release_assert(server_vc != nullptr);
    return server_vc->get_remote_endpoint();
  }

  CryptoHash hostname_hash;

  int64_t con_id;
  int transact_count;
  LSS_State state;

  // Used to verify we are recording the server
  //   transaction stat properly
  int server_trans_stat;

  // Sessions become if authentication headers
  //  are sent over them
  bool private_session;

  // Copy of the owning SM's server session sharing settings
  TSServerSessionSharingMatchType sharing_match;
  TSServerSessionSharingPoolType sharing_pool;
  //  int share_session;

  LINK(L4RServerSession, ip_hash_link);
  LINK(L4RServerSession, host_hash_link);

  // Keep track of connection limiting and a pointer to the
  // singleton that keeps track of the connection counts.
  bool enable_origin_connection_limiting;
  //ConnectionCount *connection_count;

  // The ServerSession owns the following buffer which use
  //   for parsing the headers.  The server session needs to
  //   own the buffer so we can go from a keep-alive state
  //   to being acquired and parsing the header without
  //   changing the buffer we are doing I/O on.  We can
  //   not change the buffer for I/O without issuing a
  //   an asyncronous cancel on NT
  MIOBuffer *read_buffer;

  virtual int
  populate_protocol(std::string_view *result, int size) const
  {
    auto vc = this->get_netvc();
    return vc ? vc->populate_protocol(result, size) : 0;
  }

  virtual const char *
  protocol_contains(std::string_view tag_prefix) const
  {
    auto vc = this->get_netvc();
    return vc ? vc->protocol_contains(tag_prefix) : nullptr;
  }

private:
  L4RServerSession(L4RServerSession &);

  NetVConnection *server_vc;
  int magic;

  IOBufferReader *buf_reader;
};

extern ClassAllocator<L4RServerSession> l4rServerSessionAllocator;

inline void
L4RServerSession::attach_hostname(const char *hostname)
{
  if (CRYPTO_HASH_ZERO == hostname_hash) {
    CryptoContext().hash_immediate(hostname_hash, (unsigned char *)hostname, strlen(hostname));
  }
}
