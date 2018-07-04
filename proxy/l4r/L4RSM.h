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

   L4RSM.h

   Description:


 ****************************************************************************/

#pragma once

#include "ts/ink_platform.h"
#include "P_EventSystem.h"
//#include "HttpCacheSM.h"
//#include "HttpTransact.h"
//#include "UrlRewrite.h"
//#include "HttpTunnel.h"
#include "InkAPIInternal.h"
#include "../ProxyClientTransaction.h"
//#include "HdrUtils.h"
#include <string_view>
#include <ts/History.h>
//#include "AuthHttpAdapter.h"

class L4RServerSession;

/* Enable LAZY_BUF_ALLOC to delay allocation of buffers until they
 * are actually required.
 * Enabling LAZY_BUF_ALLOC, stop Http code from allocation space
 * for header buffer and tunnel buffer. The allocation is done by
 * the net code in read_from_net when data is actually written into
 * the buffer. By allocating memory only when it is required we can
 * reduce the memory consumed by TS process.
 *
 * IMPORTANT NOTE: enable/disable LAZY_BUF_ALLOC in HttpServerSession.h
 * as well.
 */
#define LAZY_BUF_ALLOC

#define L4R_API_CONTINUE (INK_API_EVENT_EVENTS_START + 0)
#define L4R_API_ERROR (INK_API_EVENT_EVENTS_START + 1)

// The default size for http header buffers when we don't
//   need to include extra space for the document
static size_t const HTTP_HEADER_BUFFER_SIZE_INDEX = CLIENT_CONNECTION_FIRST_READ_BUFFER_SIZE_INDEX;

// We want to use a larger buffer size when reading response
//   headers from the origin server since we want to get
//   as much of the document as possible on the first read
//   Marco benchmarked about 3% ops/second improvement using
//   the larger buffer size
static size_t const HTTP_SERVER_RESP_HDR_BUFFER_INDEX = BUFFER_SIZE_INDEX_8K;

class HttpServerSession;
class AuthHttpAdapter;

class L4RSM;
typedef int (L4RSM::*L4RSMHandler)(int event, void *data);

enum HttpVC_t {
  HTTP_UNKNOWN = 0,
  HTTP_UA_VC,
  HTTP_SERVER_VC,
  HTTP_TRANSFORM_VC,
  HTTP_CACHE_READ_VC,
  HTTP_CACHE_WRITE_VC,
  HTTP_RAW_SERVER_VC
};

enum BackgroundFill_t {
  BACKGROUND_FILL_NONE = 0,
  BACKGROUND_FILL_STARTED,
  BACKGROUND_FILL_ABORTED,
  BACKGROUND_FILL_COMPLETED,
};

extern ink_mutex debug_sm_list_mutex;

struct L4RVCTableEntry {
  VConnection *vc;
  MIOBuffer *read_buffer;
  MIOBuffer *write_buffer;
  VIO *read_vio;
  VIO *write_vio;
  L4RSMHandler vc_handler;
  HttpVC_t vc_type;
  bool eos;
  bool in_tunnel;
};

struct L4RVCTable {
  static const int vc_table_max_entries = 4;
  L4RVCTable();

  L4RVCTableEntry *new_entry();
  L4RVCTableEntry *find_entry(VConnection *);
  L4RVCTableEntry *find_entry(VIO *);
  void remove_entry(L4RVCTableEntry *);
  void cleanup_entry(L4RVCTableEntry *);
  void cleanup_all();
  bool is_table_clear() const;

private:
  L4RVCTableEntry vc_table[vc_table_max_entries];
};

inline bool
L4RVCTable::is_table_clear() const
{
  for (const auto &i : vc_table) {
    if (i.vc != nullptr) {
      return false;
    }
  }
  return true;
}

struct HttpTransformInfo {
  L4RVCTableEntry *entry;
  VConnection *vc;

  HttpTransformInfo() : entry(nullptr), vc(nullptr) {}
};

enum {
  HTTP_SM_MAGIC_ALIVE = 0x0000FEED,
  HTTP_SM_MAGIC_DEAD  = 0xDEADFEED,
};

enum {
  HTTP_SM_POST_UNKNOWN     = 0,
  HTTP_SM_POST_UA_FAIL     = 1,
  HTTP_SM_POST_SERVER_FAIL = 2,
  HTTP_SM_POST_SUCCESS     = 3,
};

enum {
  HTTP_SM_TRANSFORM_OPEN   = 0,
  HTTP_SM_TRANSFORM_CLOSED = 1,
  HTTP_SM_TRANSFORM_FAIL   = 2,
};

enum L4RApiState_t {
  L4R_API_NO_CALLOUT,
  L4R_API_IN_CALLOUT,
  L4R_API_DEFERED_CLOSE,
  L4R_API_DEFERED_SERVER_ERROR,
};

enum HttpPluginTunnel_t {
  HTTP_NO_PLUGIN_TUNNEL = 0,
  HTTP_PLUGIN_AS_SERVER,
  HTTP_PLUGIN_AS_INTERCEPT,
};

class CoreUtils;
class PluginVCCore;

class PostDataBuffers
{
public:
  PostDataBuffers() { Debug("http_redirect", "[PostDataBuffers::PostDataBuffers]"); }
  MIOBuffer *postdata_copy_buffer            = nullptr;
  IOBufferReader *postdata_copy_buffer_start = nullptr;
  IOBufferReader *ua_buffer_reader           = nullptr;
  bool post_data_buffer_done                 = false;

  void clear();
  void init(IOBufferReader *ua_reader);
  void copy_partial_post_data();
  IOBufferReader *get_post_data_buffer_clone_reader();
  void
  set_post_data_buffer_done(bool done)
  {
    post_data_buffer_done = done;
  }
  bool
  get_post_data_buffer_done()
  {
    return post_data_buffer_done;
  }
  bool
  is_valid()
  {
    return postdata_copy_buffer_start != nullptr;
  }

  ~PostDataBuffers();
};

class L4RSM : public Continuation
{
  //friend class HttpPagesHandler;
  friend class CoreUtils;

public:
  L4RSM();
  void cleanup();
  virtual void destroy();

  static L4RSM *allocate();
  //L4RVCTableEntry *get_ua_entry(); // Added to get the ua_entry pointer  - YTS-TEAM

  void init();

  void attach_client_session(BasicProxyClientTransaction *client_vc_arg, IOBufferReader *buffer_reader);

  // Called by httpSessionManager so that we can reset
  //  the session timeouts and initiate a read while
  //  holding the lock for the server session
  void attach_server_session(L4RServerSession *s);

  // Used to read attributes of
  // the current active server session
  L4RServerSession *
  get_server_session()
  {
    return server_session;
  }

  // Called by transact to prevent reset problems
  //  failed PUSH requests
  void set_ua_half_close_flag();

  // Debugging routines to dump the SM history, hdrs
  void dump_state_on_assert();

  // Functions for manipulating api hooks
  void txn_hook_append(TSHttpHookID id, INKContInternal *cont);
  void txn_hook_prepend(TSHttpHookID id, INKContInternal *cont);
  APIHook *txn_hook_get(TSHttpHookID id);

  bool is_private();

  /// Get the protocol stack for the inbound (client, user agent) connection.
  /// @arg result [out] Array to store the results
  /// @arg n [in] Size of the array @a result.
  int populate_client_protocol(std::string_view *result, int n) const;
  const char *client_protocol_contains(std::string_view tag_prefix) const;
  std::string_view find_proto_string(HTTPVersion version) const;

  int64_t sm_id      = -1;
  unsigned int magic = HTTP_SM_MAGIC_DEAD;

  // YTS Team, yamsat Plugin
  bool enable_redirection = false; // To check if redirection is enabled
  char *redirect_url    = nullptr; // url for force redirect (provide users a functionality to redirect to another url when needed)
  int redirect_url_len  = 0;
  int redirection_tries = 0;        // To monitor number of redirections
  int64_t transfered_bytes = 0;     // Added to calculate POST data
  bool post_failed         = false; // Added to identify post failure
  bool debug_on            = false; // Transaction specific debug flag

protected:
  int reentrancy_count = 0;

  L4RVCTable vc_table;

  L4RVCTableEntry *ua_entry = nullptr;
  void remove_ua_entry();

public:
  L4RClientTransaction *ua_txn   = nullptr;
  BackgroundFill_t background_fill = BACKGROUND_FILL_NONE;
  // AuthHttpAdapter authAdapter;
  void set_http_schedule(Continuation *);
  int get_http_schedule(int event, void *data);

  History<HISTORY_DEFAULT_SIZE> history;

protected:
  IOBufferReader *ua_buffer_reader     = nullptr;
  IOBufferReader *ua_raw_buffer_reader = nullptr;

  L4RVCTableEntry *server_entry    = nullptr;
  L4RServerSession *server_session = nullptr;

  /* Because we don't want to take a session from a shared pool if we know that it will be private,
   * but we cannot set it to private until we have an attached server session.
   * So we use this variable to indicate that
   * we should create a new connection and then once we attach the session we'll mark it as private.
   */
  bool will_be_private_ss              = false;
  int shared_session_retries           = 0;
  IOBufferReader *server_buffer_reader = nullptr;
  void remove_server_entry();

  HttpTransformInfo transform_info;
  HttpTransformInfo post_transform_info;
  /// Set if plugin client / user agents are active.
  /// Need primarily for cleanup.
  bool has_active_plugin_agents = false;

  L4RSMHandler default_handler = nullptr;
  Action *pending_action        = nullptr;
  Continuation *schedule_cont   = nullptr;

  void start_sub_sm();

  int main_handler(int event, void *data);
  int tunnel_handler(int event, void *data);
  int tunnel_handler_push(int event, void *data);
  int tunnel_handler_post(int event, void *data);

  // YTS Team, yamsat Plugin
  int tunnel_handler_for_partial_post(int event, void *data);

  //void tunnel_handler_post_or_put(HttpTunnelProducer *p);

  int tunnel_handler_100_continue(int event, void *data);
  int tunnel_handler_cache_fill(int event, void *data);
  int state_read_client_request_header(int event, void *data);
  int state_watch_for_client_abort(int event, void *data);
  int state_read_push_response_header(int event, void *data);
  int state_srv_lookup(int event, void *data);
  int state_hostdb_lookup(int event, void *data);
  int state_hostdb_reverse_lookup(int event, void *data);
  int state_mark_os_down(int event, void *data);
  int state_handle_stat_page(int event, void *data);
  int state_auth_callback(int event, void *data);
  int state_add_to_list(int event, void *data);
  int state_remove_from_list(int event, void *data);

  // Y! ebalsa: remap handlers
  int state_remap_request(int event, void *data);
  void do_remap_request(bool);

  // Cache Handlers
  int state_cache_open_read(int event, void *data);
  int state_cache_open_write(int event, void *data);

  // Http Server Handlers
  int state_http_server_open(int event, void *data);
  int state_raw_http_server_open(int event, void *data);
  int state_send_server_request_header(int event, void *data);
  int state_acquire_server_read(int event, void *data);
  int state_read_server_response_header(int event, void *data);

  // API
  int state_request_wait_for_transform_read(int event, void *data);
  int state_response_wait_for_transform_read(int event, void *data);
  int state_common_wait_for_transform_read(HttpTransformInfo *t_info, L4RSMHandler tunnel_handler, int event, void *data);

  // Tunnel event handlers
  //int tunnel_handler_server(int event, HttpTunnelProducer *p);
  //int tunnel_handler_ua(int event, HttpTunnelConsumer *c);
  //int tunnel_handler_ua_push(int event, HttpTunnelProducer *p);
  //int tunnel_handler_100_continue_ua(int event, HttpTunnelConsumer *c);
  //int tunnel_handler_cache_write(int event, HttpTunnelConsumer *c);
  //int tunnel_handler_cache_read(int event, HttpTunnelProducer *p);
  //int tunnel_handler_post_ua(int event, HttpTunnelProducer *c);
  //int tunnel_handler_post_server(int event, HttpTunnelConsumer *c);
  //int tunnel_handler_ssl_producer(int event, HttpTunnelProducer *p);
  //int tunnel_handler_ssl_consumer(int event, HttpTunnelConsumer *p);
  //int tunnel_handler_transform_write(int event, HttpTunnelConsumer *c);
  //int tunnel_handler_transform_read(int event, HttpTunnelProducer *p);
  //int tunnel_handler_plugin_agent(int event, HttpTunnelConsumer *c);

  void do_hostdb_lookup();
  void do_hostdb_reverse_lookup();
  void do_cache_lookup_and_read();
  void do_http_server_open(bool raw = false);
  void send_origin_throttled_response();
  void do_setup_post_tunnel(HttpVC_t to_vc_type);
  void do_auth_callout();
  void do_api_callout();
  void do_api_callout_internal();
  void do_redirect();
  void redirect_request(const char *redirect_url, const int redirect_len);
  void do_drain_request_body();

  void wait_for_full_body();

  virtual void handle_api_return();
  void handle_server_setup_error(int event, void *data);
  void handle_http_server_open();
  void handle_post_failure();
  void mark_host_failure(HostDBInfo *info, time_t time_down);
  void mark_server_down_on_client_abort();
  void release_server_session(bool serve_from_cache = false);
  void set_ua_abort(HttpTransact::AbortState_t ua_abort, int event);
  int write_header_into_buffer(HTTPHdr *h, MIOBuffer *b);
  int write_response_header_into_buffer(HTTPHdr *h, MIOBuffer *b);
  void setup_blind_tunnel_port();
  void setup_client_header_nca();
  void setup_client_read_request_header();
  void setup_push_read_response_header();
  void setup_server_read_response_header();
  void setup_cache_lookup_complete_api();
  void setup_server_send_request();
  void setup_server_send_request_api();
  //HttpTunnelProducer *setup_server_transfer();
  void setup_server_transfer_to_cache_only();
  //HttpTunnelProducer *setup_cache_read_transfer();
  void setup_internal_transfer(L4RSMHandler handler);
  void setup_error_transfer();
  void setup_100_continue_transfer();
  //HttpTunnelProducer *setup_push_transfer_to_cache();
  void setup_transform_to_server_transfer();
  void setup_cache_write_transfer(HttpCacheSM *c_sm, VConnection *source_vc, HTTPInfo *store_info, int64_t skip_bytes,
                                  const char *name);
  void issue_cache_update();
  void perform_cache_write_action();
  void perform_transform_cache_write_action();
  void perform_nca_cache_action();
  void setup_blind_tunnel(bool send_response_hdr, IOBufferReader *initial = nullptr);
  //HttpTunnelProducer *setup_server_transfer_to_transform();
  //HttpTunnelProducer *setup_transfer_from_transform();
  //HttpTunnelProducer *setup_cache_transfer_to_transform();
  //HttpTunnelProducer *setup_transfer_from_transform_to_cache_only();
  //void setup_plugin_agents(HttpTunnelProducer *p);

  HttpTransact::StateMachineAction_t last_action     = HttpTransact::SM_ACTION_UNDEFINED;
  int (L4RSM::*m_last_state)(int event, void *data) = nullptr;
  virtual void set_next_state();
  void call_transact_and_set_next_state(TransactEntryFunc_t f);

  //bool is_http_server_eos_truncation(HttpTunnelProducer *);
  bool is_bg_fill_necessary(HttpTunnelConsumer *c);
  int find_server_buffer_size();
  int find_http_resp_buffer_size(int64_t cl);
  int64_t server_transfer_init(MIOBuffer *buf, int hdr_size);

public:
  // TODO:  Now that bodies can be empty, should the body counters be set to -1 ? TS-2213
  // Stats & Logging Info
  int client_request_hdr_bytes       = 0;
  int64_t client_request_body_bytes  = 0;
  int server_request_hdr_bytes       = 0;
  int64_t server_request_body_bytes  = 0;
  int server_response_hdr_bytes      = 0;
  int64_t server_response_body_bytes = 0;
  int client_response_hdr_bytes      = 0;
  int64_t client_response_body_bytes = 0;
  int cache_response_hdr_bytes       = 0;
  int64_t cache_response_body_bytes  = 0;
  int pushed_response_hdr_bytes      = 0;
  int64_t pushed_response_body_bytes = 0;
  bool client_tcp_reused             = false;
  // Info about client's SSL connection.
  bool client_ssl_reused          = false;
  bool client_connection_is_ssl   = false;
  const char *client_protocol     = "-";
  const char *client_sec_protocol = "-";
  const char *client_cipher_suite = "-";
  int server_transact_count       = 0;
  bool server_connection_is_ssl   = false;
  bool is_waiting_for_full_body   = false;
  bool is_using_post_buffer       = false;

  TransactionMilestones milestones;
  ink_hrtime api_timer = 0;
  // The next two enable plugins to tag the state machine for
  // the purposes of logging so the instances can be correlated
  // with the source plugin.
  const char *plugin_tag = nullptr;
  int64_t plugin_id      = 0;

  // hooks_set records whether there are any hooks relevant
  //  to this transaction.  Used to avoid costly calls
  //  do_api_callout_internal()
  bool hooks_set = false;

protected:
  TSHttpHookID cur_hook_id = TS_HTTP_LAST_HOOK;
  APIHook *cur_hook        = nullptr;

  //
  // Continuation time keeper
  int64_t prev_hook_start_time = 0;

  int cur_hooks                = 0;
  L4RApiState_t callout_state = L4R_API_NO_CALLOUT;

  // api_hooks must not be changed directly
  //  Use txn_hook_{ap,pre}pend so hooks_set is
  //  updated
  HttpAPIHooks api_hooks;

  // The terminate flag is set by handlers and checked by the
  //   main handler who will terminate the state machine
  //   when the flag is set
  bool terminate_sm         = false;
  bool kill_this_async_done = false;
  bool parse_range_done     = false;
  virtual int kill_this_async_hook(int event, void *data);
  void kill_this();
  void update_stats();
  void transform_cleanup(TSHttpHookID hook, HttpTransformInfo *info);
  bool is_transparent_passthrough_allowed();
  void plugin_agents_cleanup();

public:
  LINK(L4RSM, debug_link);

public:
  bool set_server_session_private(bool private_session);
  bool
  is_dying() const
  {
    return terminate_sm;
  }

  int
  client_connection_id() const
  {
    return _client_connection_id;
  }

  int
  client_transaction_id() const
  {
    return _client_transaction_id;
  }

private:
  //PostDataBuffers _postbuf;
  int _client_connection_id = -1, _client_transaction_id = -1;
};

inline L4RSM *
L4RSM::allocate()
{
  extern ClassAllocator<L4RSM> l4rSMAllocator;
  return l4rSMAllocator.alloc();
}

