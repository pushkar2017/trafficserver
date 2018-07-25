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

   L4rSM.h

   Description:


 ****************************************************************************/

#pragma once

#include "ts/ink_platform.h"
#include "P_EventSystem.h"
#include "BaseSM.h"
#include "HttpTransact.h"
#include "UrlRewrite.h"
#include "L4rTunnel.h"
#include "InkAPIInternal.h"
#include "../ProxyClientTransaction.h"
#include "HdrUtils.h"
#include <string_view>
#include <ts/History.h>

class L4rSM;
typedef int (L4rSM::*L4rSMHandler)(int event, void *data);

struct L4rVCTableEntry {
  VConnection *vc;
  MIOBuffer *read_buffer;
  MIOBuffer *write_buffer;
  VIO *read_vio;
  VIO *write_vio;
  L4rSMHandler vc_handler;
  HttpVC_t vc_type;
  bool eos;
  bool in_tunnel;
};

struct L4rVCTable {
  static const int vc_table_max_entries = 4;
  L4rVCTable();

  L4rVCTableEntry *new_entry();
  L4rVCTableEntry *find_entry(VConnection *);
  L4rVCTableEntry *find_entry(VIO *);
  void remove_entry(L4rVCTableEntry *);
  void cleanup_entry(L4rVCTableEntry *);
  void cleanup_all();
  bool is_table_clear() const;

private:
  L4rVCTableEntry vc_table[vc_table_max_entries];
};

inline bool
L4rVCTable::is_table_clear() const
{
  for (const auto &i : vc_table) {
    if (i.vc != nullptr) {
      return false;
    }
  }
  return true;
}


class L4rSM : public BaseSM
{
  friend class HttpPagesHandler;
  friend class CoreUtils;

public:
  L4rSM();
  void cleanup();
  virtual void destroy();

  static L4rSM *allocate();
  L4rVCTableEntry *get_ua_entry(); // Added to get the ua_entry pointer  - YTS-TEAM

  void init();

  void attach_client_session(ProxyClientTransaction *client_vc_arg, IOBufferReader *buffer_reader);

  virtual HttpTransact::State & get_state() { return t_state; }
  virtual int64_t get_sm_id() { return sm_id; }
  virtual void setPluginTag(const char *tag) { plugin_tag = tag; }
  virtual void setPluginId(int64_t id) { plugin_id = id; }

  // Called by httpSessionManager so that we can reset
  //  the session timeouts and initiate a read while
  //  holding the lock for the server session
  void attach_server_session(HttpServerSession *s);

  // Used to read attributes of
  // the current active server session
  HttpServerSession *
  get_server_session()
  {
    return server_session;
  }

  // Called by transact.  Updates are fire and forget
  //  so there are no callbacks and are safe to do
  //  directly from transact
  void do_hostdb_update_if_necessary();

  // Called by transact to prevent reset problems
  //  failed PUSH requests
  void set_ua_half_close_flag();

  // Called by either state_hostdb_lookup() or directly
  //   by the HostDB in the case of inline completion
  // Handles the setting of all state necessary before
  //   calling transact to process the hostdb lookup
  // A NULL 'r' argument indicates the hostdb lookup failed
  void process_hostdb_info(HostDBInfo *r);
  void process_srv_info(HostDBInfo *r);

  // Called from InkAPI.cc which acquires the state machine lock
  //  before calling
  int state_api_callback(int event, void *data);
  int state_api_callout(int event, void *data);

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

  bool debug_on            = false; // Transaction specific debug flag

  HttpTransact::State t_state;

protected:
  int reentrancy_count = 0;

  L4rTunnel tunnel;

  L4rVCTable vc_table;

  L4rVCTableEntry *ua_entry = nullptr;
  void remove_ua_entry();

public:
  ProxyClientTransaction *ua_txn   = nullptr;
  void set_http_schedule(Continuation *);
  int get_http_schedule(int event, void *data);

  History<HISTORY_DEFAULT_SIZE> history;

protected:
  IOBufferReader *ua_buffer_reader     = nullptr;
  IOBufferReader *ua_raw_buffer_reader = nullptr;

  L4rVCTableEntry *server_entry     = nullptr;
  HttpServerSession *server_session = nullptr;

  /* Because we don't want to take a session from a shared pool if we know that it will be private,
   * but we cannot set it to private until we have an attached server session.
   * So we use this variable to indicate that
   * we should create a new connection and then once we attach the session we'll mark it as private.
   */
  bool will_be_private_ss              = true;
  int shared_session_retries           = 0;
  IOBufferReader *server_buffer_reader = nullptr;
  void remove_server_entry();

  /// Set if plugin client / user agents are active.
  /// Need primarily for cleanup.
  bool has_active_plugin_agents = false;

  L4rSMHandler default_handler = nullptr;
  Action *pending_action        = nullptr;
  Continuation *schedule_cont   = nullptr;

  void start_sub_sm();

  int main_handler(int event, void *data);

  int state_read_client_request_header(int event, void *data);
  int state_watch_for_client_abort(int event, void *data);
  int state_srv_lookup(int event, void *data);
  int state_hostdb_lookup(int event, void *data);
  int state_hostdb_reverse_lookup(int event, void *data);
  int state_mark_os_down(int event, void *data);
  int state_auth_callback(int event, void *data);
  int state_add_to_list(int event, void *data);
  int state_remove_from_list(int event, void *data);

  // Http Server Handlers
  int state_http_server_open(int event, void *data);
  int state_raw_http_server_open(int event, void *data);
  int state_acquire_server_read(int event, void *data);

  void do_hostdb_lookup();
  void do_hostdb_reverse_lookup();
  void do_http_server_open(bool raw = false);
  void do_auth_callout();
  void do_api_callout();
  void do_api_callout_internal();

  void wait_for_full_body();

  virtual void handle_api_return();
  void handle_server_setup_error(int event, void *data);
  void handle_http_server_open();
  void mark_host_failure(HostDBInfo *info, time_t time_down);
  void mark_server_down_on_client_abort();
  void release_server_session(bool serve_from_cache = false);
  void set_ua_abort(HttpTransact::AbortState_t ua_abort, int event);
  void setup_server_send_request();
  void setup_server_send_request_api();
  void setup_internal_transfer(L4rSMHandler handler);
  void setup_error_transfer();
  void presetup_tunnel();
  void setup_blind_tunnel(bool send_response_hdr, IOBufferReader *initial = nullptr);
  void setup_blind_tunnel_port();
  int state_send_server_request_header(int event, void *data);

  int tunnel_handler_ssl_consumer(int event, L4rTunnelConsumer *c);
  int tunnel_handler_ssl_producer(int event, L4rTunnelProducer *p);
  int tunnel_handler(int event, void *data);

  HttpTransact::StateMachineAction_t last_action     = HttpTransact::SM_ACTION_UNDEFINED;
  int (HttpSM::*m_last_state)(int event, void *data) = nullptr;
  virtual void set_next_state();
  void call_transact_and_set_next_state(TransactEntryFunc_t f);

  bool is_http_server_eos_truncation(HttpTunnelProducer *);
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
  HttpApiState_t callout_state = HTTP_API_NO_CALLOUT;

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
  bool is_transparent_passthrough_allowed();

public:
  LINK(L4rSM, l4rdebug_link);

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
  int _client_connection_id = -1, _client_transaction_id = -1;
};

inline L4rSM *
L4rSM::allocate()
{
  extern ClassAllocator<L4rSM> l4rSMAllocator;
  return l4rSMAllocator.alloc();
}

inline void
L4rSM::remove_ua_entry()
{
  vc_table.remove_entry(ua_entry);
  ua_entry = nullptr;
}

inline void
L4rSM::remove_server_entry()
{
  if (server_entry) {
    vc_table.remove_entry(server_entry);
    server_entry = nullptr;
  }
}

