/** @file

  L4R state machine

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

#include "../ProxyClientTransaction.h"
#include "L4rSM.h"
// TODO: Remove later once we abstract out the common enums etc. into a
// common file
#include "HttpSM.h"
#include "HttpTransactHeaders.h"
#include "ProxyConfig.h"
#include "HttpServerSession.h"
#include "HttpDebugNames.h"
#include "HttpSessionManager.h"
#include "P_Cache.h"
#include "P_Net.h"
#include "StatPages.h"
#include "Log.h"
#include "LogAccessHttp.h"
#include "PluginVC.h"
#include "ReverseProxy.h"
#include "RemapProcessor.h"
#include "Transform.h"
#include "P_SSLConfig.h"
#include "HttpPages.h"
#include "IPAllow.h"
#include "ts/I_Layout.h"

#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <algorithm>
#include <atomic>

#define DEFAULT_RESPONSE_BUFFER_SIZE_INDEX 6 // 8K
#define DEFAULT_REQUEST_BUFFER_SIZE_INDEX 6  // 8K
#define MIN_CONFIG_BUFFER_SIZE_INDEX 5       // 4K

#define lsm_release_assert(EX)              \
  {                                         \
    if (!(EX)) {                            \
      this->dump_state_on_assert();         \
      _ink_assert(#EX, __FILE__, __LINE__); \
    }                                       \
  }

extern TunnelHashMap TunnelMap;

DList(L4rSM, l4rdebug_link) l4rdebug_sm_list;
ink_mutex l4rdebug_sm_list_mutex;

static const char *str_100_continue_response = "HTTP/1.1 100 Continue\r\n\r\n";
static const int len_100_continue_response   = strlen(str_100_continue_response);

namespace
{
/// Update the milestone state given the milestones and timer.
inline void
milestone_update_api_time(TransactionMilestones &milestones, ink_hrtime &api_timer)
{
  // Bit of funkiness - we set @a api_timer to be the negative value when we're tracking
  // non-active API time. In that case we need to make a note of it and flip the value back
  // to positive.
  if (api_timer) {
    ink_hrtime delta;
    bool active = api_timer >= 0;
    if (!active) {
      api_timer = -api_timer;
    }
    delta     = Thread::get_hrtime_updated() - api_timer;
    api_timer = 0;
    // Zero or negative time is a problem because we want to signal *something* happened
    // vs. no API activity at all. This can happen due to graininess or real time
    // clock adjustment.
    if (delta <= 0) {
      delta = 1;
    }

    if (0 == milestones[TS_MILESTONE_PLUGIN_TOTAL]) {
      milestones[TS_MILESTONE_PLUGIN_TOTAL] = milestones[TS_MILESTONE_SM_START];
    }
    milestones[TS_MILESTONE_PLUGIN_TOTAL] += delta;
    if (active) {
      if (0 == milestones[TS_MILESTONE_PLUGIN_ACTIVE]) {
        milestones[TS_MILESTONE_PLUGIN_ACTIVE] = milestones[TS_MILESTONE_SM_START];
      }
      milestones[TS_MILESTONE_PLUGIN_ACTIVE] += delta;
    }
  }
}
std::atomic<int64_t> next_l4rsm_id(0);
}

ClassAllocator<L4rSM> l4rSMAllocator("l4rSMAllocator");

L4rVCTable::L4rVCTable()
{
  memset(&vc_table, 0, sizeof(vc_table));
}

L4rVCTableEntry *
L4rVCTable::new_entry()
{
  for (int i = 0; i < vc_table_max_entries; i++) {
    if (vc_table[i].vc == nullptr) {
      return vc_table + i;
    }
  }

  ink_release_assert(0);
  return nullptr;
}

L4rVCTableEntry *
L4rVCTable::find_entry(VConnection *vc)
{
  for (int i = 0; i < vc_table_max_entries; i++) {
    if (vc_table[i].vc == vc) {
      return vc_table + i;
    }
  }

  return nullptr;
}

L4rVCTableEntry *
L4rVCTable::find_entry(VIO *vio)
{
  for (int i = 0; i < vc_table_max_entries; i++) {
    if (vc_table[i].read_vio == vio || vc_table[i].write_vio == vio) {
      ink_assert(vc_table[i].vc != nullptr);
      return vc_table + i;
    }
  }

  return nullptr;
}

// bool L4rVCTable::remove_entry(HttpVCEntry* e)
//
//    Deallocates all buffers from the associated
//      entry and re-initializes it's other fields
//      for reuse
//
void
L4rVCTable::remove_entry(L4rVCTableEntry *e)
{
  ink_assert(e->vc == nullptr || e->in_tunnel);
  e->vc  = nullptr;
  e->eos = false;
  if (e->read_buffer) {
    free_MIOBuffer(e->read_buffer);
    e->read_buffer = nullptr;
  }
  if (e->write_buffer) {
    free_MIOBuffer(e->write_buffer);
    e->write_buffer = nullptr;
  }
  e->read_vio   = nullptr;
  e->write_vio  = nullptr;
  e->vc_handler = nullptr;
  e->vc_type    = HTTP_UNKNOWN;
  e->in_tunnel  = false;
}

// bool L4rVCTable::cleanup_entry(HttpVCEntry* e)
//
//    Closes the associate vc for the entry,
//     and the call remove_entry
//
void
L4rVCTable::cleanup_entry(L4rVCTableEntry *e)
{
  ink_assert(e->vc);
  if (e->in_tunnel == false) {
    // Update stats
    switch (e->vc_type) {
    case HTTP_UA_VC:
      // proxy.process.http.current_client_transactions is decremented in HttpSM::destroy
      break;
    default:
      // This covers:
      // HTTP_UNKNOWN, HTTP_SERVER_VC, HTTP_TRANSFORM_VC, HTTP_CACHE_READ_VC,
      // HTTP_CACHE_WRITE_VC, HTTP_RAW_SERVER_VC
      break;
    }

    e->vc->do_io_close();
    e->vc = nullptr;
  }
  remove_entry(e);
}

void
L4rVCTable::cleanup_all()
{
  for (int i = 0; i < vc_table_max_entries; i++) {
    if (vc_table[i].vc != nullptr) {
      cleanup_entry(vc_table + i);
    }
  }
}

#define SMDebug(tag, ...) SpecificDebug(debug_on, tag, __VA_ARGS__)

#define REMEMBER(e, r)                             \
  {                                                \
    history.push_back(MakeSourceLocation(), e, r); \
  }

#ifdef STATE_ENTER
#undef STATE_ENTER
#endif
#define STATE_ENTER(state_name, event)                                                                    \
  {                                                                                                       \
    /*ink_assert (magic == HTTP_SM_MAGIC_ALIVE); */ REMEMBER(event, reentrancy_count);                    \
    SMDebug("l4r", "[%" PRId64 "] [%s, %s]", sm_id, #state_name, HttpDebugNames::get_event_name(event)); \
  }

#define L4R_SM_SET_DEFAULT_HANDLER(_h)   \
  {                                       \
    REMEMBER(NO_EVENT, reentrancy_count); \
    default_handler = _h;                 \
  }

// Layer 4 Routing State Machine
L4rSM::L4rSM() //: Continuation(nullptr)
{
  ink_zero(vc_table);
}

void
L4rSM::cleanup()
{
  t_state.destroy();
  api_hooks.clear();

  // t_state.content_control.cleanup();

  HttpConfig::release(t_state.http_config_param);

  mutex.clear();
  magic    = HTTP_SM_MAGIC_DEAD;
  debug_on = false;
}

void
L4rSM::destroy()
{
  cleanup();
  l4rSMAllocator.free(this);
}

void
L4rSM::init()
{
  milestones[TS_MILESTONE_SM_START] = Thread::get_hrtime();

  magic = HTTP_SM_MAGIC_ALIVE;

  // Unique state machine identifier
  sm_id                    = next_l4rsm_id++;
  t_state.state_machine_id = sm_id;
  // TODO: Fix this wrong type
  t_state.state_machine    = reinterpret_cast<HttpSM *>(this);

  t_state.http_config_param = HttpConfig::acquire();

  // Simply point to the global config for the time being, no need to copy this
  // entire struct if nothing is going to change it.
  t_state.txn_conf = &t_state.http_config_param->oride;

  t_state.init();

  // Added to skip dns if the document is in cache. DNS will be forced if there is a ip based ACL in
  // cache control or parent.config or if the doc_in_cache_skip_dns is disabled or if http caching is disabled
  // TODO: This probably doesn't honor this as a per-transaction overridable config.
  t_state.force_dns = (ip_rule_in_CacheControlTable() || t_state.parent_params->parent_table->ipMatch ||
                       !(t_state.txn_conf->doc_in_cache_skip_dns) || !(t_state.txn_conf->cache_http));

  SET_HANDLER(&L4rSM::main_handler);

#ifdef USE_L4R_DEBUG_LISTS
  ink_mutex_acquire(&l4rdebug_sm_list_mutex);
  debug_sm_list.push(this);
  ink_mutex_release(&l4rdebug_sm_list_mutex);
#endif
}

void
L4rSM::set_ua_half_close_flag()
{
  ua_txn->set_half_close_flag(true);
}

inline void
L4rSM::do_api_callout()
{
  if (hooks_set) {
    do_api_callout_internal();
  } else {
    handle_api_return();
  }
}

int
L4rSM::state_add_to_list(int event, void * /* data ATS_UNUSED */)
{
#if 0
  // The list if for stat pages and general debugging
  //   The config variable exists mostly to allow us to
  //   measure an performance drop during benchmark runs
  if (t_state.http_config_param->enable_http_info) {
    STATE_ENTER(&L4rSM::state_add_to_list, event);
    ink_assert(event == EVENT_NONE || event == EVENT_INTERVAL);

    int bucket = ((unsigned int)sm_id % HTTP_LIST_BUCKETS);

    MUTEX_TRY_LOCK(lock, HttpSMList[bucket].mutex, mutex->thread_holding);
    // the client_vc`s timeout events can be triggered, so we should not
    // reschedule the http_sm when the lock is not acquired.
    // FIXME: the sm_list may miss some http_sms when the lock contention
    if (lock.is_locked()) {
      HttpSMList[bucket].sm_list.push(this);
    }
  }
#endif

  t_state.api_next_action = HttpTransact::SM_ACTION_API_SM_START;
  do_api_callout();
  return EVENT_DONE;
}

int
L4rSM::state_remove_from_list(int event, void * /* data ATS_UNUSED */)
{
#if 0
  // The config parameters are guaranteed not change
  //   across the life of a transaction so it safe to
  //   check the config here and use it determine
  //   whether we need to strip ourselves off of the
  //   state page list
  if (t_state.http_config_param->enable_http_info) {
    STATE_ENTER(&L4rSM::state_remove_from_list, event);
    ink_assert(event == EVENT_NONE || event == EVENT_INTERVAL);

    int bucket = ((unsigned int)sm_id % HTTP_LIST_BUCKETS);

    MUTEX_TRY_LOCK(lock, HttpSMList[bucket].mutex, mutex->thread_holding);
    if (!lock.is_locked()) {
      L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::state_remove_from_list);
      mutex->thread_holding->schedule_in(this, HTTP_LIST_RETRY);
      return EVENT_DONE;
    }

    HttpSMList[bucket].sm_list.remove(this);
  }
#endif

  return this->kill_this_async_hook(EVENT_NONE, nullptr);
}

int
L4rSM::kill_this_async_hook(int /* event ATS_UNUSED */, void * /* data ATS_UNUSED */)
{
  // In the base L4rSM, we don't have anything to
  //   do here.  subclasses can override this function
  //   to do their own asynchronous cleanup
  // So We're now ready to finish off the state machine
  terminate_sm         = true;
  kill_this_async_done = true;

  return EVENT_DONE;
}

void
L4rSM::start_sub_sm()
{
  tunnel.init(this, mutex);
}

void
L4rSM::attach_client_session(ProxyClientTransaction *client_vc, IOBufferReader *buffer_reader)
{
  milestones[TS_MILESTONE_UA_BEGIN] = Thread::get_hrtime();
  ink_assert(client_vc != nullptr);

  NetVConnection *netvc = client_vc->get_netvc();
  if (!netvc) {
    return;
  }
  ua_txn = client_vc;

  // It seems to be possible that the ua_txn pointer will go stale before log entries for this HTTP transaction are
  // generated.  Therefore, collect information that may be needed for logging from the ua_txn object at this point.
  //
  _client_transaction_id = ua_txn->get_transaction_id();
  {
    auto p = ua_txn->get_parent();
    if (p) {
      _client_connection_id = p->connection_id();
    }
  }

  // Collect log & stats information
  client_tcp_reused         = !(ua_txn->is_first_transaction());
  SSLNetVConnection *ssl_vc = dynamic_cast<SSLNetVConnection *>(netvc);
  if (ssl_vc != nullptr) {
    client_connection_is_ssl = true;
    client_ssl_reused        = ssl_vc->getSSLSessionCacheHit();
    const char *protocol     = ssl_vc->getSSLProtocol();
    client_sec_protocol      = protocol ? protocol : "-";
    const char *cipher       = ssl_vc->getSSLCipherSuite();
    client_cipher_suite      = cipher ? cipher : "-";
    if (!client_tcp_reused) {
      // Copy along the TLS handshake timings
      milestones[TS_MILESTONE_TLS_HANDSHAKE_START] = ssl_vc->sslHandshakeBeginTime;
      milestones[TS_MILESTONE_TLS_HANDSHAKE_END]   = ssl_vc->sslHandshakeEndTime;
    }
  }
  const char *protocol_str = client_vc->get_protocol_string();
  client_protocol          = protocol_str ? protocol_str : "-";

  ink_release_assert(ua_txn->get_half_close_flag() == false);
  mutex = client_vc->mutex;
  HTTP_INCREMENT_DYN_STAT(http_current_client_transactions_stat);
  if (ua_txn->debug()) {
    debug_on = true;
  }

  start_sub_sm();

  // Allocate a user agent entry in the state machine's
  //   vc table
  ua_entry          = vc_table.new_entry();
  ua_entry->vc      = client_vc;
  ua_entry->vc_type = HTTP_UA_VC;

  ats_ip_copy(&t_state.client_info.src_addr, netvc->get_remote_addr());
  ats_ip_copy(&t_state.client_info.dst_addr, netvc->get_local_addr());
  t_state.client_info.dst_addr.port() = netvc->get_local_port();
  t_state.client_info.is_transparent  = netvc->get_is_transparent();
  t_state.backdoor_request            = !client_vc->hooks_enabled();
  t_state.client_info.port_attribute  = static_cast<HttpProxyPort::TransportType>(netvc->attributes);

  // Record api hook set state
  hooks_set = client_vc->has_hooks();

  // Setup for parsing the header
  ua_buffer_reader     = buffer_reader;
  ua_entry->vc_handler = &L4rSM::state_read_client_request_header;
  t_state.hdr_info.client_request.destroy();
  t_state.hdr_info.client_request.create(HTTP_TYPE_REQUEST);

  // Prepare raw reader which will live until we are sure this is HTTP indeed
#if 0
  if (is_transparent_passthrough_allowed()) {
    ua_raw_buffer_reader = buffer_reader->clone();
  }
#endif

  // We first need to run the transaction start hook.  Since
  //  this hook maybe asynchronous, we need to disable IO on
  //  client but set the continuation to be the state machine
  //  so if we get an timeout events the sm handles them
  ua_entry->read_vio = client_vc->do_io_read(this, 0, buffer_reader->mbuf);

  /////////////////////////
  // set up timeouts     //
  /////////////////////////
  client_vc->set_inactivity_timeout(HRTIME_SECONDS(t_state.http_config_param->accept_no_activity_timeout));
  client_vc->set_active_timeout(HRTIME_SECONDS(t_state.txn_conf->transaction_active_timeout_in));

  ++reentrancy_count;
  // Add our state sm to the sm list
  state_add_to_list(EVENT_NONE, nullptr);
  // This is another external entry point and it is possible for the state machine to get terminated
  // while down the call chain from @c state_add_to_list. So we need to use the reentrancy_count to
  // prevent cleanup there and do it here as we return to the external caller.
  if (terminate_sm == true && reentrancy_count == 1) {
    kill_this();
  } else {
    --reentrancy_count;
    ink_assert(reentrancy_count >= 0);
  }
}

void
L4rSM::setup_blind_tunnel(bool send_response_hdr, IOBufferReader *initial)
{
  L4rTunnelConsumer *c_ua;
  L4rTunnelConsumer *c_os;
  L4rTunnelProducer *p_ua;
  L4rTunnelProducer *p_os;
  MIOBuffer *from_ua_buf = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);
  MIOBuffer *to_ua_buf   = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);
  IOBufferReader *r_from = from_ua_buf->alloc_reader();
  IOBufferReader *r_to   = to_ua_buf->alloc_reader();

  milestones[TS_MILESTONE_SERVER_BEGIN_WRITE] = Thread::get_hrtime();
  if (send_response_hdr) {
    //client_response_hdr_bytes = write_response_header_into_buffer(&t_state.hdr_info.client_response, to_ua_buf);
    if (initial && initial->read_avail()) {
      int64_t avail = initial->read_avail();
      to_ua_buf->write(initial, avail);
      initial->consume(avail);
    }
  } else {
    client_response_hdr_bytes = 0;
  }

  client_request_body_bytes = 0;
  if (ua_raw_buffer_reader != nullptr) {
    client_request_body_bytes += from_ua_buf->write(ua_raw_buffer_reader, client_request_hdr_bytes);
    ua_raw_buffer_reader->dealloc();
    ua_raw_buffer_reader = nullptr;
  }

  // Next order of business if copy the remaining data from the
  //  header buffer into new buffer
  client_request_body_bytes += from_ua_buf->write(ua_buffer_reader);

  L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::tunnel_handler);

  p_os =
    tunnel.add_producer(server_entry->vc, -1, r_to, &L4rSM::tunnel_handler_ssl_producer, L4R_SERVER, "http server - tunnel");

  c_ua = tunnel.add_consumer(ua_entry->vc, server_entry->vc, &L4rSM::tunnel_handler_ssl_consumer, L4R_CLIENT,
                             "user agent - tunnel");

  p_ua = tunnel.add_producer(ua_entry->vc, -1, r_from, &L4rSM::tunnel_handler_ssl_producer, L4R_CLIENT, "user agent - tunnel");

  c_os = tunnel.add_consumer(server_entry->vc, ua_entry->vc, &L4rSM::tunnel_handler_ssl_consumer, L4R_SERVER,
                             "http server - tunnel");

  // Make the tunnel aware that the entries are bi-directional
  tunnel.chain(c_os, p_os);
  tunnel.chain(c_ua, p_ua);

  ua_entry->in_tunnel     = true;
  server_entry->in_tunnel = true;

  tunnel.tunnel_run();

  // If we're half closed, we got a FIN from the client. Forward it on to the origin server
  // now that we have the tunnel operational.
  if (ua_txn && ua_txn->get_half_close_flag()) {
    p_ua->vc->do_io_shutdown(IO_SHUTDOWN_READ);
  }
}

void
L4rSM::setup_blind_tunnel_port()
{
  NetVConnection *netvc     = ua_txn->get_netvc();
  SSLNetVConnection *ssl_vc = dynamic_cast<SSLNetVConnection *>(netvc);
  int host_len;
  if (ssl_vc && ssl_vc->GetSNIMapping()) {
    if (!t_state.hdr_info.client_request.url_get()->host_get(&host_len)) {
      // the URL object has not been created in the start of the transaction. Hence, we need to create the URL here
      URL u;

      t_state.hdr_info.client_request.create(HTTP_TYPE_REQUEST);
      t_state.hdr_info.client_request.method_set(HTTP_METHOD_CONNECT, HTTP_LEN_CONNECT);
      t_state.hdr_info.client_request.url_create(&u);
      u.scheme_set(URL_SCHEME_TUNNEL, URL_LEN_TUNNEL);
      t_state.hdr_info.client_request.url_set(&u);
      auto *hs = TunnelMap.find(ssl_vc->serverName);
      if (hs != nullptr) {
        t_state.hdr_info.client_request.url_get()->host_set(hs->hostname, hs->len);
        if (hs->port > 0) {
          t_state.hdr_info.client_request.url_get()->port_set(hs->port);
        } else {
          t_state.hdr_info.client_request.url_get()->port_set(t_state.state_machine->ua_txn->get_netvc()->get_local_port());
        }
      } else {
        t_state.hdr_info.client_request.url_get()->host_set(ssl_vc->serverName, strlen(ssl_vc->serverName));
        t_state.hdr_info.client_request.url_get()->port_set(t_state.state_machine->ua_txn->get_netvc()->get_local_port());
      }
    }
  } else {
    char new_host[INET6_ADDRSTRLEN];
    L4rSM *state_machine = reinterpret_cast<L4rSM *>(t_state.state_machine);
    ats_ip_ntop(state_machine->ua_txn->get_netvc()->get_local_addr(), new_host, sizeof(new_host));

    t_state.hdr_info.client_request.url_get()->host_set(new_host, strlen(new_host));
    t_state.hdr_info.client_request.url_get()->port_set(state_machine->ua_txn->get_netvc()->get_local_port());
  }
  call_transact_and_set_next_state(HttpTransact::HandleBlindTunnel);
}

void
L4rSM::wait_for_full_body()
{
}

int
L4rSM::state_read_client_request_header(int event, void *data)
{
  STATE_ENTER(&HttpSM::state_read_client_request_header, event);

  ink_assert(ua_entry->read_vio == (VIO *)data);
  ink_assert(server_entry == nullptr);
  ink_assert(server_session == nullptr);

  int bytes_used = 0;
  ink_assert(ua_entry->eos == false);

  NetVConnection *netvc = ua_txn->get_netvc();
  if (!netvc && event != VC_EVENT_EOS) {
    return 0;
  }

  switch (event) {
  case VC_EVENT_READ_READY:
  case VC_EVENT_READ_COMPLETE:
    // More data to parse
    break;

  case VC_EVENT_EOS:
    ua_entry->eos = true;
    if ((client_request_hdr_bytes > 0) && /*is_transparent_passthrough_allowed() && */(ua_raw_buffer_reader != nullptr)) {
      break;
    }
  // Fall through
  case VC_EVENT_ERROR:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT:
    // The user agent is hosed.  Close it &
    //   bail on the state machine
    vc_table.cleanup_entry(ua_entry);
    ua_entry = nullptr;
    set_ua_abort(HttpTransact::ABORTED, event);
    terminate_sm = true;
    return 0;
  }

  // Reset the inactivity timeout if this is the first
  //   time we've been called.  The timeout had been set to
  //   the accept timeout by the ProxyClientTransaction
  //
  if ((ua_buffer_reader->read_avail() > 0) && (client_request_hdr_bytes == 0)) {
    milestones[TS_MILESTONE_UA_FIRST_READ] = Thread::get_hrtime();
    ua_txn->set_inactivity_timeout(HRTIME_SECONDS(t_state.txn_conf->transaction_no_activity_timeout_in));
  }
  /////////////////////
  // tokenize header //
  /////////////////////

  client_request_hdr_bytes += bytes_used;
  ParseResult state;

  // Check to see if we are over the hdr size limit
  if (client_request_hdr_bytes > t_state.txn_conf->request_hdr_max_size) {
    SMDebug("http", "client header bytes were over max header size; treating as a bad request");
    state = PARSE_RESULT_ERROR;
  }

  // We need to handle EOS as well as READ_READY because the client
  // may have sent all of the data already followed by a fIN and that
  // should be OK.
  if (/*is_transparent_passthrough_allowed() && */ua_raw_buffer_reader != nullptr) {
    bool do_blind_tunnel = false;
    // If we had a parse error and we're done reading data
    // blind tunnel
    if ((event == VC_EVENT_READ_READY || event == VC_EVENT_EOS) && state == PARSE_RESULT_ERROR) {
      do_blind_tunnel = true;

      // If we had a GET request that has data after the
      // get request, do blind tunnel
    } else if (state == PARSE_RESULT_DONE && t_state.hdr_info.client_request.method_get_wksidx() == HTTP_WKSIDX_GET &&
               ua_buffer_reader->read_avail() > 0 && !t_state.hdr_info.client_request.is_keep_alive_set()) {
      do_blind_tunnel = true;
    }
    if (do_blind_tunnel) {
      SMDebug("http", "[%" PRId64 "] first request on connection failed parsing, switching to passthrough.", sm_id);

      t_state.transparent_passthrough = true;

      // Turn off read eventing until we get the
      // blind tunnel infrastructure set up
      if (netvc) {
        netvc->do_io_read(this, 0, nullptr);
      }

      /* establish blind tunnel */
      //setup_blind_tunnel_port();

      // Setting half close means we will send the FIN when we've written all of the data.
      if (event == VC_EVENT_EOS) {
        this->set_ua_half_close_flag();
        t_state.client_info.keep_alive = HTTP_NO_KEEPALIVE;
      }
      return 0;
    }
  }

  // Check to see if we are done parsing the header
  if (state != PARSE_RESULT_CONT || ua_entry->eos || (state == PARSE_RESULT_CONT && event == VC_EVENT_READ_COMPLETE)) {
    if (ua_raw_buffer_reader != nullptr) {
      ua_raw_buffer_reader->dealloc();
      ua_raw_buffer_reader = nullptr;
    }
    ua_entry->vc_handler                         = &L4rSM::state_watch_for_client_abort;
    milestones[TS_MILESTONE_UA_READ_HEADER_DONE] = Thread::get_hrtime();
  }

  switch (state) {
  case PARSE_RESULT_ERROR:
    SMDebug("http", "[%" PRId64 "] error parsing client request header", sm_id);

    // Disable further I/O on the client
    ua_entry->read_vio->nbytes = ua_entry->read_vio->ndone;

    call_transact_and_set_next_state(HttpTransact::BadRequest);
    break;

  case PARSE_RESULT_CONT:
    if (ua_entry->eos) {
      SMDebug("http_seq", "[%" PRId64 "] EOS before client request parsing finished", sm_id);
      set_ua_abort(HttpTransact::ABORTED, event);

      // Disable further I/O on the client
      ua_entry->read_vio->nbytes = ua_entry->read_vio->ndone;

      call_transact_and_set_next_state(HttpTransact::BadRequest);
      break;
    } else if (event == VC_EVENT_READ_COMPLETE) {
      SMDebug("http_parse", "[%" PRId64 "] VC_EVENT_READ_COMPLETE and PARSE CONT state", sm_id);
      break;
    } else {
      if (is_transparent_passthrough_allowed() && ua_raw_buffer_reader != nullptr &&
          ua_raw_buffer_reader->get_current_block()->write_avail() <= 0) {
        // Disable passthrough regardless of eventual parsing failure or success -- otherwise
        // we either have to consume some data or risk blocking the writer.
        ua_raw_buffer_reader->dealloc();
        ua_raw_buffer_reader = nullptr;
      }
      ua_entry->read_vio->reenable();
      return VC_EVENT_CONT;
    }
  case PARSE_RESULT_DONE:
    SMDebug("http", "[%" PRId64 "] done parsing client request header", sm_id);

    ua_txn->set_session_active();

    if (t_state.hdr_info.client_request.version_get() == HTTPVersion(1, 1) &&
        (t_state.hdr_info.client_request.method_get_wksidx() == HTTP_WKSIDX_POST ||
         t_state.hdr_info.client_request.method_get_wksidx() == HTTP_WKSIDX_PUT) &&
        t_state.http_config_param->send_100_continue_response) {
      int len            = 0;
      const char *expect = t_state.hdr_info.client_request.value_get(MIME_FIELD_EXPECT, MIME_LEN_EXPECT, &len);
      // When receive an "Expect: 100-continue" request from client, ATS sends a "100 Continue" response to client
      // immediately, before receive the real response from original server.
      if ((len == HTTP_LEN_100_CONTINUE) && (strncasecmp(expect, HTTP_VALUE_100_CONTINUE, HTTP_LEN_100_CONTINUE) == 0)) {
        int64_t alloc_index = buffer_size_to_index(len_100_continue_response);
        if (ua_entry->write_buffer) {
          free_MIOBuffer(ua_entry->write_buffer);
          ua_entry->write_buffer = nullptr;
        }
        ua_entry->write_buffer    = new_MIOBuffer(alloc_index);
        IOBufferReader *buf_start = ua_entry->write_buffer->alloc_reader();

        t_state.hdr_info.client_request.m_100_continue_required = true;

        SMDebug("http_seq", "send 100 Continue response to client");
        int64_t nbytes      = ua_entry->write_buffer->write(str_100_continue_response, len_100_continue_response);
        ua_entry->write_vio = ua_txn->do_io_write(this, nbytes, buf_start);
      }
    }

    if (t_state.hdr_info.client_request.method_get_wksidx() == HTTP_WKSIDX_TRACE ||
        (t_state.hdr_info.client_request.get_content_length() == 0 &&
         t_state.client_info.transfer_encoding != HttpTransact::CHUNKED_ENCODING)) {
      // Enable further IO to watch for client aborts
      ua_entry->read_vio->reenable();
    } else {
      // Disable further I/O on the client since there could
      //  be body that we are tunneling POST/PUT/CONNECT or
      //  extension methods and we can't issue another
      //  another IO later for the body with a different buffer
      ua_entry->read_vio->nbytes = ua_entry->read_vio->ndone;
    }

    call_transact_and_set_next_state(HttpTransact::ModifyRequest);

    break;
  default:
    ink_assert(!"not reached");
  }

  return 0;
}

int
L4rSM::state_watch_for_client_abort(int event, void *data)
{
  STATE_ENTER(&L4rSM::state_watch_for_client_abort, event);

  ink_assert(ua_entry->read_vio == (VIO *)data || ua_entry->write_vio == (VIO *)data);
  ink_assert(ua_entry->vc == ua_txn);

  switch (event) {
  /* EOS means that the client has initiated the connection shut down.
   * Only half close the client connection so ATS can read additional
   * data that may still be sent from the server and send it to the
   * client.
   */
  case VC_EVENT_EOS: {
    // We got an early EOS.
    NetVConnection *netvc = ua_txn->get_netvc();
    if (ua_txn->allow_half_open()) {
      if (netvc) {
        netvc->do_io_shutdown(IO_SHUTDOWN_READ);
      }
      ua_entry->eos = true;
    } else {
      ua_txn->do_io_close();
      ua_buffer_reader = nullptr;
      vc_table.cleanup_entry(ua_entry);
      ua_entry = nullptr;
      terminate_sm = true; // Just die already, the requester is gone
    }
    break;
  }
  case VC_EVENT_ERROR:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT: {
    // Disable further I/O on the client
    if (ua_entry->read_vio) {
      ua_entry->read_vio->nbytes = ua_entry->read_vio->ndone;
    }
    mark_server_down_on_client_abort();
    milestones[TS_MILESTONE_UA_CLOSE] = Thread::get_hrtime();
    set_ua_abort(HttpTransact::ABORTED, event);

    terminate_sm = true;
    break;
  }
  case VC_EVENT_READ_COMPLETE:
  // XXX Work around for TS-1233.
  case VC_EVENT_READ_READY:
    //  Ignore.  Could be a pipelined request.  We'll get to  it
    //    when we finish the current transaction
    break;
  case VC_EVENT_WRITE_READY:
    // 100-continue handler
    ink_assert(t_state.hdr_info.client_request.m_100_continue_required);
    ua_entry->write_vio->reenable();
    break;
  case VC_EVENT_WRITE_COMPLETE:
    // 100-continue handler
    ink_assert(t_state.hdr_info.client_request.m_100_continue_required);
    if (ua_entry->write_buffer) {
      ink_assert(ua_entry->write_vio && !ua_entry->write_vio->ntodo());
      free_MIOBuffer(ua_entry->write_buffer);
      ua_entry->write_buffer = nullptr;
    }
    break;
  default:
    ink_release_assert(0);
    break;
  }

  return 0;
}

//////////////////////////////////////////////////////////////////////////////
//
//  L4rSM::state_http_server_open()
//
//////////////////////////////////////////////////////////////////////////////
int
L4rSM::state_raw_http_server_open(int event, void *data)
{
  STATE_ENTER(&L4rSM::state_raw_http_server_open, event);
  ink_assert(server_entry == nullptr);
  milestones[TS_MILESTONE_SERVER_CONNECT_END] = Thread::get_hrtime();
  NetVConnection *netvc                       = nullptr;

  pending_action = nullptr;
  switch (event) {
  case EVENT_INTERVAL:
    // If we get EVENT_INTERNAL it means that we moved the transaction
    // to a different thread in do_http_server_open.  Since we didn't
    // do any of the actual work in do_http_server_open, we have to
    // go back and do it now.
    do_http_server_open(true);
    return 0;

  case NET_EVENT_OPEN:

    // Record the VC in our table
    server_entry     = vc_table.new_entry();
    server_entry->vc = netvc = (NetVConnection *)data;
    server_entry->vc_type    = HTTP_RAW_SERVER_VC;
    t_state.current.state    = HttpTransact::CONNECTION_ALIVE;

    netvc->set_inactivity_timeout(HRTIME_SECONDS(t_state.txn_conf->transaction_no_activity_timeout_out));
    netvc->set_active_timeout(HRTIME_SECONDS(t_state.txn_conf->transaction_active_timeout_out));
    break;

  case VC_EVENT_ERROR:
  case NET_EVENT_OPEN_FAILED:
    t_state.current.state = HttpTransact::OPEN_RAW_ERROR;
    // use this value just to get around other values
    t_state.hdr_info.response_error = HttpTransact::STATUS_CODE_SERVER_ERROR;
    break;

  default:
    ink_release_assert(0);
    break;
  }

  call_transact_and_set_next_state(HttpTransact::OriginServerRawOpen);
  return 0;
}

// int L4rSM::state_api_callback(int event, void *data)

//   InkAPI.cc calls us directly here to avoid problems
//    with setting and changing the default_handler
//    function.  As such, this is an entry point
//    and needs to handle the reentrancy counter and
//    deallocation the state machine if necessary
//
int
L4rSM::state_api_callback(int event, void *data)
{
  ink_release_assert(magic == HTTP_SM_MAGIC_ALIVE);

  ink_assert(reentrancy_count >= 0);
  reentrancy_count++;

  milestone_update_api_time(milestones, api_timer);

  STATE_ENTER(&L4rSM::state_api_callback, event);

  state_api_callout(event, data);

  // The sub-handler signals when it is time for the state
  //  machine to exit.  We can only exit if we are not reentrantly
  //  called otherwise when the our call unwinds, we will be
  //  running on a dead state machine
  //
  // Because of the need for an api shutdown hook, kill_this()
  //  is also reentrant.  As such, we don't want to decrement
  //  the reentrancy count until after we run kill_this()
  //
  if (terminate_sm == true && reentrancy_count == 1) {
    kill_this();
  } else {
    reentrancy_count--;
    ink_assert(reentrancy_count >= 0);
  }

  return VC_EVENT_CONT;
}

int
L4rSM::state_api_callout(int event, void *data)
{
  // enum and variable for figuring out what the next action is after
  //   after we've finished the api state
  enum AfterApiReturn_t {
    API_RETURN_UNKNOWN = 0,
    API_RETURN_CONTINUE,
    API_RETURN_DEFERED_CLOSE,
    API_RETURN_DEFERED_SERVER_ERROR,
    API_RETURN_ERROR_JUMP,
    API_RETURN_SHUTDOWN,
    API_RETURN_INVALIDATE_ERROR
  };
  AfterApiReturn_t api_next = API_RETURN_UNKNOWN;

  if (event != EVENT_NONE) {
    STATE_ENTER(&L4rSM::state_api_callout, event);
  }

  if (api_timer < 0) {
    // This happens when either the plugin lock was missed and the hook rescheduled or
    // the transaction got an event without the plugin calling TsHttpTxnReenable().
    // The call chain does not recurse here if @a api_timer < 0 which means this call
    // is the first from an event dispatch in this case.
    milestone_update_api_time(milestones, api_timer);
  }

  switch (event) {
  case HTTP_TUNNEL_EVENT_DONE:
  // This is a reschedule via the tunnel.  Just fall through
  //
  case EVENT_INTERVAL:
    if (data != pending_action) {
      pending_action->cancel();
    }
    pending_action = nullptr;
  // FALLTHROUGH
  case EVENT_NONE:
    if (cur_hook_id == TS_HTTP_TXN_START_HOOK && t_state.client_info.port_attribute == HttpProxyPort::TRANSPORT_BLIND_TUNNEL) {
      /* Creating the request object early to set the host header and port for blind tunneling here for the
plugins required to work with sni_routing.
*/
      // Plugins triggered on txn_start_hook will get the host and port at that point
      // We've received a request on a port which we blind forward
      URL u;

      t_state.hdr_info.client_request.create(HTTP_TYPE_REQUEST);
      t_state.hdr_info.client_request.method_set(HTTP_METHOD_CONNECT, HTTP_LEN_CONNECT);
      t_state.hdr_info.client_request.url_create(&u);
      u.scheme_set(URL_SCHEME_TUNNEL, URL_LEN_TUNNEL);
      t_state.hdr_info.client_request.url_set(&u);

      NetVConnection *netvc     = ua_txn->get_netvc();
      SSLNetVConnection *ssl_vc = dynamic_cast<SSLNetVConnection *>(netvc);

      if (ssl_vc && ssl_vc->GetSNIMapping()) {
        auto *hs = TunnelMap.find(ssl_vc->serverName);
        if (hs != nullptr) {
          t_state.hdr_info.client_request.url_get()->host_set(hs->hostname, hs->len);
          if (hs->port > 0) {
            t_state.hdr_info.client_request.url_get()->port_set(hs->port);
          } else {
            //t_state.hdr_info.client_request.url_get()->port_set(t_state.state_machine->ua_txn->get_netvc()->get_local_port());
          }
        } else {
          t_state.hdr_info.client_request.url_get()->host_set(ssl_vc->serverName, strlen(ssl_vc->serverName));
          //t_state.hdr_info.client_request.url_get()->port_set(t_state.state_machine->ua_txn->get_netvc()->get_local_port());
        }
      }
    }
  // FALLTHROUGH
  case HTTP_API_CONTINUE:
    if ((cur_hook_id >= 0) && (cur_hook_id < TS_HTTP_LAST_HOOK)) {
      if (!cur_hook) {
        if (cur_hooks == 0) {
          cur_hook = http_global_hooks->get(cur_hook_id);
          cur_hooks++;
        }
      }
      // even if ua_txn is NULL, cur_hooks must
      // be incremented otherwise cur_hooks is not set to 2 and
      // transaction hooks (stored in api_hooks object) are not called.
      if (!cur_hook) {
        if (cur_hooks == 1) {
          if (ua_txn) {
            cur_hook = ua_txn->ssn_hook_get(cur_hook_id);
          }
          cur_hooks++;
        }
      }
      if (!cur_hook) {
        if (cur_hooks == 2) {
          cur_hook = api_hooks.get(cur_hook_id);
          cur_hooks++;
        }
      }
      if (cur_hook) {
        if (callout_state == HTTP_API_NO_CALLOUT) {
          callout_state = HTTP_API_IN_CALLOUT;
        }

        /* The MUTEX_TRY_LOCK macro was changed so
           that it can't handle NULL mutex'es.  The plugins
           can use null mutexes so we have to do this manually.
           We need to take a smart pointer to the mutex since
           the plugin could release it's mutex while we're on
           the callout
         */
        bool plugin_lock;
        Ptr<ProxyMutex> plugin_mutex;
        if (cur_hook->m_cont->mutex) {
          plugin_mutex = cur_hook->m_cont->mutex;
          plugin_lock  = MUTEX_TAKE_TRY_LOCK(cur_hook->m_cont->mutex, mutex->thread_holding);

          if (!plugin_lock) {
            api_timer = -Thread::get_hrtime_updated();
            L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::state_api_callout);
            ink_assert(pending_action == nullptr);
            pending_action = mutex->thread_holding->schedule_in(this, HRTIME_MSECONDS(10));
            // Should @a callout_state be reset back to HTTP_API_NO_CALLOUT here? Because the default
            // handler has been changed the value isn't important to the rest of the state machine
            // but not resetting means there is no way to reliably detect re-entrance to this state with an
            // outstanding callout.
            return 0;
          }
        } else {
          plugin_lock = false;
        }

        SMDebug("http", "[%" PRId64 "] calling plugin on hook %s at hook %p", sm_id, HttpDebugNames::get_api_hook_name(cur_hook_id),
                cur_hook);

        APIHook *hook = cur_hook;
        cur_hook      = cur_hook->next();

        if (!api_timer) {
          api_timer = Thread::get_hrtime_updated();
        }
        hook->invoke(TS_EVENT_HTTP_READ_REQUEST_HDR + cur_hook_id, this);
        if (api_timer > 0) { // true if the hook did not call TxnReenable()
          milestone_update_api_time(milestones, api_timer);
          api_timer = -Thread::get_hrtime_updated(); // set in order to track non-active callout duration
          // which means that if we get back from the invoke with api_timer < 0 we're already
          // tracking a non-complete callout from a chain so just let it ride. It will get cleaned
          // up in state_api_callback when the plugin re-enables this transaction.
        }

        if (plugin_lock) {
          Mutex_unlock(plugin_mutex, mutex->thread_holding);
        }

        return 0;
      }
    }
    // Map the callout state into api_next
    switch (callout_state) {
    case HTTP_API_NO_CALLOUT:
    case HTTP_API_IN_CALLOUT:
      if (t_state.api_modifiable_cached_resp && t_state.api_update_cached_object == HttpTransact::UPDATE_CACHED_OBJECT_PREPARE) {
        t_state.api_update_cached_object = HttpTransact::UPDATE_CACHED_OBJECT_CONTINUE;
      }
      api_next = API_RETURN_CONTINUE;
      break;
    case HTTP_API_DEFERED_CLOSE:
      api_next = API_RETURN_DEFERED_CLOSE;
      break;
    case HTTP_API_DEFERED_SERVER_ERROR:
      api_next = API_RETURN_DEFERED_SERVER_ERROR;
      break;
    default:
      ink_release_assert(0);
    }
    break;

  case HTTP_API_ERROR:
    if (callout_state == HTTP_API_DEFERED_CLOSE) {
      api_next = API_RETURN_DEFERED_CLOSE;
    } else if (cur_hook_id == TS_HTTP_TXN_CLOSE_HOOK) {
      // If we are closing the state machine, we can't
      //   jump to an error state so just continue
      api_next = API_RETURN_CONTINUE;
    } else if (t_state.api_http_sm_shutdown) {
      t_state.api_http_sm_shutdown   = false;
      t_state.cache_info.object_read = nullptr;
      release_server_session();
      terminate_sm                 = true;
      api_next                     = API_RETURN_SHUTDOWN;
      t_state.squid_codes.log_code = SQUID_LOG_TCP_DENIED;
    } else if (t_state.api_modifiable_cached_resp &&
               t_state.api_update_cached_object == HttpTransact::UPDATE_CACHED_OBJECT_PREPARE) {
      t_state.api_update_cached_object = HttpTransact::UPDATE_CACHED_OBJECT_ERROR;
      api_next                         = API_RETURN_INVALIDATE_ERROR;
    } else {
      api_next = API_RETURN_ERROR_JUMP;
    }
    break;

  default:
    ink_assert(false);
    terminate_sm = true;
    return 0;
  }

  // Now that we're completed with the api state and figured out what
  //   to do next, do it
  callout_state = HTTP_API_NO_CALLOUT;
  api_timer     = 0;
  switch (api_next) {
  case API_RETURN_CONTINUE:
    handle_api_return();
    break;
  case API_RETURN_DEFERED_CLOSE:
    ink_assert(t_state.api_next_action == HttpTransact::SM_ACTION_API_SM_SHUTDOWN);
    do_api_callout();
    break;
  case API_RETURN_DEFERED_SERVER_ERROR:
    ink_assert(t_state.api_next_action == HttpTransact::SM_ACTION_API_SEND_REQUEST_HDR);
    ink_assert(t_state.current.state != HttpTransact::CONNECTION_ALIVE);
    call_transact_and_set_next_state(HttpTransact::HandleResponse);
    break;
  case API_RETURN_ERROR_JUMP:
    call_transact_and_set_next_state(HttpTransact::HandleApiErrorJump);
    break;
  case API_RETURN_SHUTDOWN:
    break;
  case API_RETURN_INVALIDATE_ERROR:
    break;
  default:
  case API_RETURN_UNKNOWN:
    ink_release_assert(0);
  }

  return 0;
}

// void L4rSM::handle_api_return()
//
//   Figures out what to do after calling api callouts
//    have finished.  This messy and I would like
//    to come up with a cleaner way to handle the api
//    return.  The way we are doing things also makes a
//    mess of set_next_state()
//

void
L4rSM::presetup_tunnel()
{
  // Reset the inactivity timeout if this is the first
  //   time we've been called.  The timeout had been set to
  //   the accept timeout by the ProxyClientTransaction
  //
  if ((ua_buffer_reader->read_avail() > 0) && (client_request_hdr_bytes == 0)) {
    milestones[TS_MILESTONE_UA_FIRST_READ] = Thread::get_hrtime();
    ua_txn->set_inactivity_timeout(HRTIME_SECONDS(t_state.txn_conf->transaction_no_activity_timeout_in));
  }

  // Set the mode to tunnel so that we don't lookup the cache
  t_state.current.mode = HttpTransact::TUNNELLING_PROXY;

  t_state.cache_info.action = HttpTransact::CACHE_DO_NO_ACTION;
  t_state.current.mode      = HttpTransact::GENERIC_PROXY;

  t_state.transparent_passthrough = true;

  NetVConnection *netvc = ua_txn->get_netvc();

  // Turn off read eventing until we get the
  // blind tunnel infrastructure set up
  if (netvc) {
    netvc->do_io_read(this, 0, nullptr);
  }

}

void
L4rSM::handle_api_return()
{
  switch (t_state.api_next_action) {
  case HttpTransact::SM_ACTION_API_SM_START:
    L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::state_raw_http_server_open);
    do_http_server_open(true);
    return;

  case HttpTransact::SM_ACTION_API_READ_REQUEST_HDR:
  case HttpTransact::SM_ACTION_REQUEST_BUFFER_READ_COMPLETE:
  case HttpTransact::SM_ACTION_API_OS_DNS:
    call_transact_and_set_next_state(nullptr);
    return;
  case HttpTransact::SM_ACTION_API_SEND_REQUEST_HDR:
    //setup_server_send_request();
    return;
  case HttpTransact::SM_ACTION_API_SEND_RESPONSE_HDR:
    // Set back the inactivity timeout
    if (ua_txn) {
      ua_txn->set_inactivity_timeout(HRTIME_SECONDS(t_state.txn_conf->transaction_no_activity_timeout_in));
    }

    // we have further processing to do
    //  based on what t_state.next_action is
    break;
  case HttpTransact::SM_ACTION_API_SM_SHUTDOWN:
    state_remove_from_list(EVENT_NONE, nullptr);
    return;
  default:
    ink_release_assert("! Not reached");
    break;
  }

  switch (t_state.next_action) {
  case HttpTransact::SM_ACTION_SERVER_READ: {
    if (unlikely(t_state.did_upgrade_succeed)) {
      // We've successfully handled the upgrade, let's now setup
      // a blind tunnel.
      IOBufferReader *initial_data = nullptr;
      setup_blind_tunnel(true, initial_data);
    } else {
    }
    break;
  }
  case HttpTransact::SM_ACTION_SSL_TUNNEL: {
    setup_blind_tunnel(true);
    break;
  }
  default: {
    ink_release_assert(!"Should not get here");
  }
  }
}

//////////////////////////////////////////////////////////////////////////////
//
//  L4rSM::state_http_server_open()
//
//////////////////////////////////////////////////////////////////////////////
int
L4rSM::state_http_server_open(int event, void *data)
{
  SMDebug("http_track", "entered inside state_http_server_open");
  STATE_ENTER(&L4rSM::state_http_server_open, event);
  // TODO decide whether to uncomment after finish testing redirect
  // ink_assert(server_entry == NULL);
  pending_action                              = nullptr;
  milestones[TS_MILESTONE_SERVER_CONNECT_END] = Thread::get_hrtime();
  HttpServerSession *session;

  switch (event) {
  case NET_EVENT_OPEN:
    session = (TS_SERVER_SESSION_SHARING_POOL_THREAD == t_state.http_config_param->server_session_sharing_pool) ?
                THREAD_ALLOC_INIT(httpServerSessionAllocator, mutex->thread_holding) :
                httpServerSessionAllocator.alloc();
    session->sharing_pool  = static_cast<TSServerSessionSharingPoolType>(t_state.http_config_param->server_session_sharing_pool);
    session->sharing_match = static_cast<TSServerSessionSharingMatchType>(t_state.txn_conf->server_session_sharing_match);
    // If origin_max_connections or origin_min_keep_alive_connections is
    // set then we are metering the max and or min number
    // of connections per host.  Set enable_origin_connection_limiting
    // to true in the server session so it will increment and decrement
    // the connection count.
    if (t_state.txn_conf->origin_max_connections > 0 || t_state.http_config_param->origin_min_keep_alive_connections > 0) {
      SMDebug("http_ss", "[%" PRId64 "] max number of connections: %" PRIu64, sm_id, t_state.txn_conf->origin_max_connections);
      session->enable_origin_connection_limiting = true;
    }
    /*UnixNetVConnection * vc = (UnixNetVConnection*)(ua_txn->client_vc);
       UnixNetVConnection *server_vc = (UnixNetVConnection*)data;
       printf("client fd is :%d , server fd is %d\n",vc->con.fd,
       server_vc->con.fd); */
    session->attach_hostname(t_state.current.server->name);
    session->new_connection(static_cast<NetVConnection *>(data));
    session->state = HSS_ACTIVE;

    attach_server_session(session);
    if (t_state.current.request_to == HttpTransact::PARENT_PROXY) {
      session->to_parent_proxy = true;
      HTTP_INCREMENT_DYN_STAT(http_current_parent_proxy_connections_stat);
      HTTP_INCREMENT_DYN_STAT(http_total_parent_proxy_connections_stat);

    } else {
      session->to_parent_proxy = false;
    }
    handle_http_server_open();
    return 0;
  case EVENT_INTERVAL: // Delayed call from another thread
    if (server_session == nullptr) {
      do_http_server_open();
    }
    break;
  case VC_EVENT_ERROR:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case NET_EVENT_OPEN_FAILED:
    t_state.current.state = HttpTransact::CONNECTION_ERROR;
    // save the errno from the connect fail for future use (passed as negative value, flip back)
    t_state.current.server->set_connect_fail(event == NET_EVENT_OPEN_FAILED ? -reinterpret_cast<intptr_t>(data) : ECONNABORTED);

    /* If we get this error in transparent mode, then we simply can't bind to the 4-tuple to make the connection.  There's no hope
       of retries succeeding in the near future. The best option is to just shut down the connection without further comment. The
       only known cause for this is outbound transparency combined with use client target address / source port, as noted in
       TS-1424. If the keep alives desync the current connection can be attempting to rebind the 4 tuple simultaneously with the
       shut down of an existing connection. Dropping the client side will cause it to pick a new source port and recover from this
       issue.
    */
    if (EADDRNOTAVAIL == t_state.current.server->connect_result && t_state.client_info.is_transparent) {
      if (is_debug_tag_set("http_tproxy")) {
        ip_port_text_buffer ip_c, ip_s;
        Debug("http_tproxy", "Force close of client connect (%s->%s) due to EADDRNOTAVAIL [%" PRId64 "]",
              ats_ip_nptop(&t_state.client_info.src_addr.sa, ip_c, sizeof ip_c),
              ats_ip_nptop(&t_state.server_info.dst_addr.sa, ip_s, sizeof ip_s), sm_id);
      }
      t_state.client_info.keep_alive = HTTP_NO_KEEPALIVE; // part of the problem, clear it.
      terminate_sm                   = true;
    // Later we can add throttling if we need it
    //} else if (ENET_THROTTLING == t_state.current.server->connect_result) {
    //  HTTP_INCREMENT_DYN_STAT(http_origin_connections_throttled_stat);
    //  send_origin_throttled_response();
    //} else {
      call_transact_and_set_next_state(HttpTransact::HandleResponse);
    }
    return 0;

  default:
    Error("[L4rSM::state_http_server_open] Unknown event: %d", event);
    ink_release_assert(0);
    return 0;
  }

  return 0;
}

int
L4rSM::state_send_server_request_header(int event, void *data)
{
  STATE_ENTER(&L4rSM::state_send_server_request_header, event);
  ink_assert(server_entry != nullptr);
  ink_assert(server_entry->write_vio == (VIO *)data || server_entry->read_vio == (VIO *)data);

  switch (event) {
  case VC_EVENT_WRITE_READY:
    server_entry->write_vio->reenable();
    break;

  case VC_EVENT_WRITE_COMPLETE:
    // We are done sending the request header, deallocate
    //  our buffer and then decide what to do next
    free_MIOBuffer(server_entry->write_buffer);
    server_entry->write_buffer = nullptr;
    {
      // It's time to start reading the response
      //setup_server_read_response_header();
    }

    break;

  case VC_EVENT_READ_READY:
    // We already did the read for the response header and
    //  we got some data.  Wait for the request header
    //  send before dealing with it.  However, we need to
    //  disable further IO here since the whole response
    //  may be in the buffer and we can not switch buffers
    //  on the io core later
    ink_assert(server_entry->read_vio == (VIO *)data);
    // setting nbytes to ndone would disable reads and remove it from the read queue.
    // We can't do this in the epoll paradigm because we may be missing epoll errors that would
    // prevent us from leaving this state.
    // setup_server_read_response_header will trigger READ_READY to itself if there is data in the buffer.

    // server_entry->read_vio->nbytes = server_entry->read_vio->ndone;

    break;

  case VC_EVENT_EOS:
    // EOS of stream comes from the read side.  Treat it as
    //  as error if there is nothing in the read buffer.  If
    //  there is something the server may have blasted back
    //  the response before receiving the request.  Happens
    //  often with redirects
    //
    //  If we are in the middle of an api callout, it
    //    means we haven't actually sent the request yet
    //    so the stuff in the buffer is garbage and we
    //    want to ignore it
    //
    server_entry->eos = true;

    // I'm not sure about the above comment, but if EOS is received on read and we are
    // still in this state, we must have not gotten WRITE_COMPLETE.  With epoll we might not receive EOS
    // from both read and write sides of a connection so it should be handled correctly (close tunnels,
    // deallocate, etc) here with handle_server_setup_error().  Otherwise we might hang due to not shutting
    // down and never receiving another event again.
    /*if (server_buffer_reader->read_avail() > 0 && callout_state == HTTP_API_NO_CALLOUT) {
       break;
       } */

    // Nothing in the buffer
    // proceed to error
    // fallthrough

  case VC_EVENT_ERROR:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
    handle_server_setup_error(event, data);
    break;

  case VC_EVENT_READ_COMPLETE:
    // new event expected due to TS-3189
    SMDebug("http_ss", "read complete due to 0 byte do_io_read");
    break;

  default:
    ink_release_assert(0);
    break;
  }

  return 0;
}

void
L4rSM::process_srv_info(HostDBInfo *r)
{
  SMDebug("dns_srv", "beginning process_srv_info");
  t_state.hostdb_entry = Ptr<HostDBInfo>(r);

  /* we didn't get any SRV records, continue w normal lookup */
  if (!r || !r->is_srv || !r->round_robin) {
    t_state.dns_info.srv_hostname[0]    = '\0';
    t_state.dns_info.srv_lookup_success = false;
    t_state.txn_conf->srv_enabled       = false;
    SMDebug("dns_srv", "No SRV records were available, continuing to lookup %s", t_state.dns_info.lookup_name);
  } else {
    HostDBRoundRobin *rr = r->rr();
    HostDBInfo *srv      = nullptr;
    if (rr) {
      srv = rr->select_best_srv(t_state.dns_info.srv_hostname, &mutex->thread_holding->generator, ink_local_time(),
                                (int)t_state.txn_conf->down_server_timeout);
    }
    if (!srv) {
      t_state.dns_info.srv_lookup_success = false;
      t_state.dns_info.srv_hostname[0]    = '\0';
      t_state.txn_conf->srv_enabled       = false;
      SMDebug("dns_srv", "SRV records empty for %s", t_state.dns_info.lookup_name);
    } else {
      t_state.dns_info.srv_lookup_success = true;
      t_state.dns_info.srv_port           = srv->data.srv.srv_port;
      t_state.dns_info.srv_app            = srv->app;
      // t_state.dns_info.single_srv = (rr->good == 1);
      ink_assert(srv->data.srv.key == makeHostHash(t_state.dns_info.srv_hostname));
      SMDebug("dns_srv", "select SRV records %s", t_state.dns_info.srv_hostname);
    }
  }
  return;
}

void
L4rSM::process_hostdb_info(HostDBInfo *r)
{
  // Increment the refcount to our item, since we are pointing at it
  t_state.hostdb_entry = Ptr<HostDBInfo>(r);

  sockaddr const *client_addr = nullptr;
  bool use_client_addr        = t_state.http_config_param->use_client_target_addr == 1 && t_state.client_info.is_transparent &&
                         t_state.dns_info.os_addr_style == HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_DEFAULT;
  if (use_client_addr) {
    NetVConnection *vc = t_state.state_machine->ua_txn ? t_state.state_machine->ua_txn->get_netvc() : nullptr;
    if (vc) {
      client_addr = vc->get_local_addr();
      // Regardless of whether the client address matches the DNS record or not,
      // we want to use that address.  Therefore, we copy over the client address
      // info and skip the assignment from the DNS cache
      ats_ip_copy(t_state.host_db_info.ip(), client_addr);
      t_state.dns_info.os_addr_style  = HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_CLIENT;
      t_state.dns_info.lookup_success = true;
      // Leave ret unassigned, so we don't overwrite the host_db_info
    } else {
      use_client_addr = false;
    }
  }

  if (r && !r->is_failed()) {
    ink_time_t now                    = ink_local_time();
    HostDBInfo *ret                   = nullptr;
    t_state.dns_info.lookup_success   = true;
    t_state.dns_info.lookup_validated = true;

    HostDBRoundRobin *rr = r->round_robin ? r->rr() : nullptr;
    if (rr) {
      // if use_client_target_addr is set, make sure the client addr is in the results pool
      if (use_client_addr && rr->find_ip(client_addr) == nullptr) {
        SMDebug("http", "use_client_target_addr == 1. Client specified address is not in the pool, not validated.");
        t_state.dns_info.lookup_validated = false;
      } else {
        // Since the time elapsed between current time and client_request_time
        // may be very large, we cannot use client_request_time to approximate
        // current time when calling select_best_http().
        ret = rr->select_best_http(&t_state.client_info.src_addr.sa, now, static_cast<int>(t_state.txn_conf->down_server_timeout));
        // set the srv target`s last_failure
        if (t_state.dns_info.srv_lookup_success) {
          uint32_t last_failure = 0xFFFFFFFF;
          for (int i = 0; i < rr->rrcount && last_failure != 0; ++i) {
            if (last_failure > rr->info(i).app.http_data.last_failure) {
              last_failure = rr->info(i).app.http_data.last_failure;
            }
          }

          if (last_failure != 0 && (uint32_t)(now - t_state.txn_conf->down_server_timeout) < last_failure) {
            HostDBApplicationInfo app;
            app.allotment.application1 = 0;
            app.allotment.application2 = 0;
            app.http_data.last_failure = last_failure;
            hostDBProcessor.setby_srv(t_state.dns_info.lookup_name, 0, t_state.dns_info.srv_hostname, &app);
          }
        }
      }
    } else {
      if (use_client_addr && !ats_ip_addr_eq(client_addr, &r->data.ip.sa)) {
        SMDebug("http", "use_client_target_addr == 1. Comparing single addresses failed, not validated.");
        t_state.dns_info.lookup_validated = false;
      } else {
        ret = r;
      }
    }
    if (ret) {
      t_state.host_db_info = *ret;
      ink_release_assert(!t_state.host_db_info.reverse_dns);
      ink_release_assert(ats_is_ip(t_state.host_db_info.ip()));
    }
  } else {
    SMDebug("http", "[%" PRId64 "] DNS lookup failed for '%s'", sm_id, t_state.dns_info.lookup_name);

    if (!use_client_addr) {
      t_state.dns_info.lookup_success = false;
    }
    t_state.host_db_info.app.allotment.application1 = 0;
    t_state.host_db_info.app.allotment.application2 = 0;
    ink_assert(!t_state.host_db_info.round_robin);
  }

  milestones[TS_MILESTONE_DNS_LOOKUP_END] = Thread::get_hrtime();

  if (is_debug_tag_set("http_timeout")) {
    if (t_state.api_txn_dns_timeout_value != -1) {
      int foo = (int)(milestones.difference_msec(TS_MILESTONE_DNS_LOOKUP_BEGIN, TS_MILESTONE_DNS_LOOKUP_END));
      SMDebug("http_timeout", "DNS took: %d msec", foo);
    }
  }
}

//////////////////////////////////////////////////////////////////////////////
//
//  L4rSM::state_hostdb_lookup()
//
//////////////////////////////////////////////////////////////////////////////
int
L4rSM::state_hostdb_lookup(int event, void *data)
{
  STATE_ENTER(&L4rSM::state_hostdb_lookup, event);

  //    ink_assert (m_origin_server_vc == 0);
  // REQ_FLAVOR_SCHEDULED_UPDATE can be transformed into
  // REQ_FLAVOR_REVPROXY
  ink_assert(t_state.req_flavor == HttpTransact::REQ_FLAVOR_SCHEDULED_UPDATE ||
             t_state.req_flavor == HttpTransact::REQ_FLAVOR_REVPROXY || ua_entry->vc != nullptr);

  switch (event) {
  case EVENT_HOST_DB_LOOKUP:
    pending_action = nullptr;
    process_hostdb_info((HostDBInfo *)data);
    call_transact_and_set_next_state(nullptr);
    break;
  case EVENT_SRV_LOOKUP: {
    pending_action = nullptr;
    process_srv_info((HostDBInfo *)data);

    char *host_name = t_state.dns_info.srv_lookup_success ? t_state.dns_info.srv_hostname : t_state.dns_info.lookup_name;
    HostDBProcessor::Options opt;
    opt.port  = t_state.dns_info.srv_lookup_success ? t_state.dns_info.srv_port : t_state.server_info.dst_addr.host_order_port();
    opt.flags = (t_state.cache_info.directives.does_client_permit_dns_storing) ? HostDBProcessor::HOSTDB_DO_NOT_FORCE_DNS :
                                                                                 HostDBProcessor::HOSTDB_FORCE_DNS_RELOAD;
    opt.timeout        = (t_state.api_txn_dns_timeout_value != -1) ? t_state.api_txn_dns_timeout_value : 0;
    opt.host_res_style = ua_txn->get_host_res_style();

    Action *dns_lookup_action_handle =
      hostDBProcessor.getbyname_imm(this, (process_hostdb_info_pfn)&L4rSM::process_hostdb_info, host_name, 0, opt);
    if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
      ink_assert(!pending_action);
      pending_action = dns_lookup_action_handle;
    } else {
      call_transact_and_set_next_state(nullptr);
    }
  } break;
  case EVENT_HOST_DB_IP_REMOVED:
    ink_assert(!"Unexpected event from HostDB");
    break;
  default:
    ink_assert(!"Unexpected event");
  }

  return 0;
}

int
L4rSM::state_hostdb_reverse_lookup(int event, void *data)
{
  STATE_ENTER(&L4rSM::state_hostdb_reverse_lookup, event);

  // REQ_FLAVOR_SCHEDULED_UPDATE can be transformed into
  // REQ_FLAVOR_REVPROXY
  ink_assert(t_state.req_flavor == HttpTransact::REQ_FLAVOR_SCHEDULED_UPDATE ||
             t_state.req_flavor == HttpTransact::REQ_FLAVOR_REVPROXY || ua_entry->vc != nullptr);

  switch (event) {
  case EVENT_HOST_DB_LOOKUP:
    pending_action = nullptr;
    if (data) {
      t_state.request_data.hostname_str = ((HostDBInfo *)data)->hostname();
    } else {
      SMDebug("http", "[%" PRId64 "] reverse DNS lookup failed for '%s'", sm_id, t_state.dns_info.lookup_name);
    }
    call_transact_and_set_next_state(nullptr);
    break;
  default:
    ink_assert(!"Unexpected event");
  }

  return 0;
}

//////////////////////////////////////////////////////////////////////////////
//
//  L4rSM:state_mark_os_down()
//
//////////////////////////////////////////////////////////////////////////////
int
L4rSM::state_mark_os_down(int event, void *data)
{
  HostDBInfo *mark_down = nullptr;

  if (event == EVENT_HOST_DB_LOOKUP && data) {
    HostDBInfo *r = (HostDBInfo *)data;

    if (r->round_robin) {
      // Look for the entry we need mark down in the round robin
      ink_assert(t_state.current.server != nullptr);
      ink_assert(t_state.current.request_to == HttpTransact::ORIGIN_SERVER);
      if (t_state.current.server) {
        mark_down = r->rr()->find_ip(&t_state.current.server->dst_addr.sa);
      }
    } else {
      // No longer a round robin, check to see if our address is the same
      if (ats_ip_addr_eq(t_state.host_db_info.ip(), r->ip())) {
        mark_down = r;
      }
    }

    if (mark_down) {
      mark_host_failure(mark_down, t_state.request_sent_time);
    }
  }
  // We either found our entry or we did not.  Either way find
  //  the entry we should use now
  return state_hostdb_lookup(event, data);
}

int
L4rSM::main_handler(int event, void *data)
{
  ink_release_assert(magic == HTTP_SM_MAGIC_ALIVE);

  L4rSMHandler jump_point = nullptr;
  ink_assert(reentrancy_count >= 0);
  reentrancy_count++;

  // Don't use the state enter macro since it uses history
  //  space that we don't care about
  SMDebug("http", "[%" PRId64 "] [L4rSM::main_handler, %s]", sm_id, HttpDebugNames::get_event_name(event));

  L4rVCTableEntry *vc_entry = nullptr;

  if (data != nullptr) {
    // Only search the VC table if the event could have to
    //  do with a VIO to save a few cycles

    if (event < VC_EVENT_EVENTS_START + 100) {
      vc_entry = vc_table.find_entry((VIO *)data);
    }
  }

  if (vc_entry) {
    jump_point = vc_entry->vc_handler;
    ink_assert(jump_point != (L4rSMHandler) nullptr);
    ink_assert(vc_entry->vc != (VConnection *)nullptr);
    (this->*jump_point)(event, data);
  } else {
    ink_assert(default_handler != (L4rSMHandler) nullptr);
    (this->*default_handler)(event, data);
  }

  // The sub-handler signals when it is time for the state
  //  machine to exit.  We can only exit if we are not reentrantly
  //  called otherwise when the our call unwinds, we will be
  //  running on a dead state machine
  //
  // Because of the need for an api shutdown hook, kill_this()
  // is also reentrant.  As such, we don't want to decrement
  // the reentrancy count until after we run kill_this()
  //
  if (terminate_sm == true && reentrancy_count == 1) {
    kill_this();
  } else {
    reentrancy_count--;
    ink_assert(reentrancy_count >= 0);
  }

  return (VC_EVENT_CONT);
}

bool
L4rSM::is_http_server_eos_truncation(HttpTunnelProducer *p)
{
  if ((p->do_dechunking || p->do_chunked_passthru) && p->chunked_handler.truncation) {
    return true;
  }

  //////////////////////////////////////////////////////////////
  // If we did not get or did not trust the origin server's   //
  //  content-length, read_content_length is unset.  The      //
  //  only way the end of the document is signaled is the     //
  //  origin server closing the connection.  However, we      //
  //  need to protect against the document getting truncated  //
  //  because the origin server crashed.  The following       //
  //  tabled outlines when we mark the server read as failed  //
  //                                                          //
  //    No C-L               :  read success                  //
  //    Received byts < C-L  :  read failed (=> Cache Abort)  //
  //    Received byts == C-L :  read success                  //
  //    Received byts > C-L  :  read success                  //
  //////////////////////////////////////////////////////////////
  int64_t cl = t_state.hdr_info.server_response.get_content_length();

  if (cl != UNDEFINED_COUNT && cl > server_response_body_bytes) {
    SMDebug("http", "[%" PRId64 "] server EOS after %" PRId64 " bytes, expected %" PRId64, sm_id, server_response_body_bytes, cl);
    return true;
  } else {
    return false;
  }
}

bool
L4rSM::is_bg_fill_necessary(HttpTunnelConsumer *c)
{
  ink_assert(c->vc_type == HT_HTTP_CLIENT);

  if (c->producer->alive &&          // something there to read
                                     //      server_entry && server_entry->vc &&              // from an origin server
                                     //      server_session && server_session->get_netvc() && // which is still open and valid
      c->producer->num_consumers > 1 // with someone else reading it
  ) {
    HttpTunnelProducer *p = nullptr;

    if (!server_entry || !server_entry->vc || !server_session || !server_session->get_netvc()) {
      // return true if we have finished the reading from OS when client aborted
      p = c->producer->self_consumer ? c->producer->self_consumer->producer : c->producer;
      if (p->vc_type == HT_HTTP_SERVER && p->read_success) {
        return true;
      } else {
        return false;
      }
    }
    // If threshold is 0.0 or negative then do background
    //   fill regardless of the content length.  Since this
    //   is floating point just make sure the number is near zero
    if (t_state.txn_conf->background_fill_threshold <= 0.001) {
      return true;
    }

    int64_t ua_cl = t_state.hdr_info.client_response.get_content_length();

    if (ua_cl > 0) {
      int64_t ua_body_done = c->bytes_written - client_response_hdr_bytes;
      float pDone          = (float)ua_body_done / ua_cl;

      // If we got a good content length.  Check to make sure that we haven't already
      //  done more the content length since that would indicate the content-length
      //  is bogus.  If we've done more than the threshold, continue the background fill
      if (pDone <= 1.0 && pDone > t_state.txn_conf->background_fill_threshold) {
        return true;
      } else {
        SMDebug("http", "[%" PRId64 "] no background.  Only %%%f of %%%f done [%" PRId64 " / %" PRId64 " ]", sm_id, pDone,
                t_state.txn_conf->background_fill_threshold, ua_body_done, ua_cl);
      }
    }
  }

  return false;
}

int
L4rSM::state_srv_lookup(int event, void *data)
{
  STATE_ENTER(&L4rSM::state_srv_lookup, event);

  ink_assert(t_state.req_flavor == HttpTransact::REQ_FLAVOR_SCHEDULED_UPDATE ||
             t_state.req_flavor == HttpTransact::REQ_FLAVOR_REVPROXY || ua_entry->vc != nullptr);

  switch (event) {
  case EVENT_SRV_LOOKUP:
    pending_action = nullptr;
    process_srv_info((HostDBInfo *)data);
    break;
  case EVENT_SRV_IP_REMOVED:
    ink_assert(!"Unexpected SRV event from HostDB. What up, Eric?");
    break;
  default:
    ink_assert(!"Unexpected event");
  }

  return 0;
}

void
L4rSM::do_hostdb_lookup()
{
  /*
      //////////////////////////////////////////
      // if a connection to the origin server //
      // is currently opened --- close it.    //
      //////////////////////////////////////////
      if (m_origin_server_vc != 0) {
     origin_server_close(CLOSE_CONNECTION);
     if (m_response_body_tunnel_buffer_.buf() != 0)
         m_response_body_tunnel_buffer_.reset();
      }
      */

  ink_assert(t_state.dns_info.lookup_name != nullptr);
  ink_assert(pending_action == nullptr);

  milestones[TS_MILESTONE_DNS_LOOKUP_BEGIN] = Thread::get_hrtime();

  if (t_state.txn_conf->srv_enabled) {
    char d[MAXDNAME];

    // Look at the next_hop_scheme to determine what scheme to put in the SRV lookup
    unsigned int scheme_len = sprintf(d, "_%s._tcp.", hdrtoken_index_to_wks(t_state.next_hop_scheme));
    ink_strlcpy(d + scheme_len, t_state.server_info.name, sizeof(d) - scheme_len);

    SMDebug("dns_srv", "Beginning lookup of SRV records for origin %s", d);

    HostDBProcessor::Options opt;
    if (t_state.api_txn_dns_timeout_value != -1) {
      opt.timeout = t_state.api_txn_dns_timeout_value;
    }
    Action *srv_lookup_action_handle =
      hostDBProcessor.getSRVbyname_imm(this, (process_srv_info_pfn)&L4rSM::process_srv_info, d, 0, opt);

    if (srv_lookup_action_handle != ACTION_RESULT_DONE) {
      ink_assert(!pending_action);
      pending_action = srv_lookup_action_handle;
    } else {
      char *host_name = t_state.dns_info.srv_lookup_success ? t_state.dns_info.srv_hostname : t_state.dns_info.lookup_name;
      opt.port        = t_state.dns_info.srv_lookup_success ?
                   t_state.dns_info.srv_port :
                   t_state.server_info.dst_addr.isValid() ? t_state.server_info.dst_addr.host_order_port() :
                                                            t_state.hdr_info.client_request.port_get();
      opt.flags = (t_state.cache_info.directives.does_client_permit_dns_storing) ? HostDBProcessor::HOSTDB_DO_NOT_FORCE_DNS :
                                                                                   HostDBProcessor::HOSTDB_FORCE_DNS_RELOAD;
      opt.timeout        = (t_state.api_txn_dns_timeout_value != -1) ? t_state.api_txn_dns_timeout_value : 0;
      opt.host_res_style = ua_txn->get_host_res_style();

      Action *dns_lookup_action_handle =
        hostDBProcessor.getbyname_imm(this, (process_hostdb_info_pfn)&L4rSM::process_hostdb_info, host_name, 0, opt);
      if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
        ink_assert(!pending_action);
        pending_action = dns_lookup_action_handle;
      } else {
        call_transact_and_set_next_state(nullptr);
      }
    }
    return;
  } else { /* we aren't using SRV stuff... */
    SMDebug("http_seq", "[L4rSM::do_hostdb_lookup] Doing DNS Lookup");

    // If there is not a current server, we must be looking up the origin
    //  server at the beginning of the transaction
    int server_port = t_state.current.server ?
                        t_state.current.server->dst_addr.host_order_port() :
                        t_state.server_info.dst_addr.isValid() ? t_state.server_info.dst_addr.host_order_port() :
                                                                 t_state.hdr_info.client_request.port_get();

    if (t_state.api_txn_dns_timeout_value != -1) {
      SMDebug("http_timeout", "beginning DNS lookup. allowing %d mseconds for DNS lookup", t_state.api_txn_dns_timeout_value);
    }

    HostDBProcessor::Options opt;
    opt.port  = server_port;
    opt.flags = (t_state.cache_info.directives.does_client_permit_dns_storing) ? HostDBProcessor::HOSTDB_DO_NOT_FORCE_DNS :
                                                                                 HostDBProcessor::HOSTDB_FORCE_DNS_RELOAD;
    opt.timeout        = (t_state.api_txn_dns_timeout_value != -1) ? t_state.api_txn_dns_timeout_value : 0;
    opt.host_res_style = ua_txn->get_host_res_style();

    Action *dns_lookup_action_handle = hostDBProcessor.getbyname_imm(this, (process_hostdb_info_pfn)&L4rSM::process_hostdb_info,
                                                                     t_state.dns_info.lookup_name, 0, opt);

    if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
      ink_assert(!pending_action);
      pending_action = dns_lookup_action_handle;
    } else {
      call_transact_and_set_next_state(nullptr);
    }
    return;
  }
  ink_assert(!"not reached");
  return;
}

void
L4rSM::do_hostdb_reverse_lookup()
{
  ink_assert(t_state.dns_info.lookup_name != nullptr);
  ink_assert(pending_action == nullptr);

  SMDebug("http_seq", "[L4rSM::do_hostdb_reverse_lookup] Doing reverse DNS Lookup");

  IpEndpoint addr;
  ats_ip_pton(t_state.dns_info.lookup_name, &addr.sa);
  Action *dns_lookup_action_handle = hostDBProcessor.getbyaddr_re(this, &addr.sa);

  if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
    ink_assert(!pending_action);
    pending_action = dns_lookup_action_handle;
  }
  return;
}

void
L4rSM::do_hostdb_update_if_necessary()
{
  int issue_update = 0;

  if (t_state.current.server == nullptr /*|| plugin_tunnel_type != HTTP_NO_PLUGIN_TUNNEL*/) {
    // No server, so update is not necessary
    return;
  }
  // If we failed back over to the origin server, we don't have our
  //   hostdb information anymore which means we shouldn't update the hostdb
  if (!ats_ip_addr_eq(&t_state.current.server->dst_addr.sa, t_state.host_db_info.ip())) {
    SMDebug("http", "[%" PRId64 "] skipping hostdb update due to server failover", sm_id);
    return;
  }

  if (t_state.updated_server_version != HostDBApplicationInfo::HTTP_VERSION_UNDEFINED) {
    // we may have incorrectly assumed that the hostdb had the wrong version of
    // http for the server because our first few connect attempts to the server
    // failed, causing us to downgrade our requests to a lower version and changing
    // our information about the server version.
    //
    // This test therefore just issues the update only if the hostdb version is
    // in fact different from the version we want the value to be updated to.
    if (t_state.host_db_info.app.http_data.http_version != t_state.updated_server_version) {
      t_state.host_db_info.app.http_data.http_version = t_state.updated_server_version;
      issue_update |= 1;
    }

    t_state.updated_server_version = HostDBApplicationInfo::HTTP_VERSION_UNDEFINED;
  }
  // Check to see if we need to report or clear a connection failure
  if (t_state.current.server->had_connect_fail()) {
    issue_update |= 1;
    mark_host_failure(&t_state.host_db_info, t_state.client_request_time);
  } else {
    if (t_state.host_db_info.app.http_data.last_failure != 0) {
      t_state.host_db_info.app.http_data.last_failure = 0;
      issue_update |= 1;
      char addrbuf[INET6_ADDRPORTSTRLEN];
      SMDebug("http", "[%" PRId64 "] hostdb update marking IP: %s as up", sm_id,
              ats_ip_nptop(&t_state.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));
    }

    if (t_state.dns_info.srv_lookup_success && t_state.dns_info.srv_app.http_data.last_failure != 0) {
      t_state.dns_info.srv_app.http_data.last_failure = 0;
      hostDBProcessor.setby_srv(t_state.dns_info.lookup_name, 0, t_state.dns_info.srv_hostname, &t_state.dns_info.srv_app);
      SMDebug("http", "[%" PRId64 "] hostdb update marking SRV: %s as up", sm_id, t_state.dns_info.srv_hostname);
    }
  }

  if (issue_update) {
    hostDBProcessor.setby(t_state.current.server->name, strlen(t_state.current.server->name), &t_state.current.server->dst_addr.sa,
                          &t_state.host_db_info.app);
  }

  char addrbuf[INET6_ADDRPORTSTRLEN];
  SMDebug("http", "server info = %s", ats_ip_nptop(&t_state.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));
  return;
}

//////////////////////////////////////////////////////////////////////////
//
//  L4rSM::do_http_server_open()
//
//////////////////////////////////////////////////////////////////////////
void
L4rSM::do_http_server_open(bool raw)
{
  // Hardcode for now
  // Why is server still nullptr, figure this out
  t_state.current.server = new HttpTransact::ConnectionAttributes;
  in_addr_t localhost = 16777343;
  ats_ip4_set(&(t_state.current.server->dst_addr.sa), localhost, htons(9001));

  int ip_family = t_state.current.server->dst_addr.sa.sa_family;
  auto fam_name = ats_ip_family_name(ip_family);
  SMDebug("http_track", "entered inside do_http_server_open ][%.*s]", static_cast<int>(fam_name.size()), fam_name.data());

  // Make sure we are on the "right" thread
  if (ua_txn) {
    if ((pending_action = ua_txn->adjust_thread(this, EVENT_INTERVAL, nullptr))) {
      return; // Go away if we reschedule
    }
  }
  pending_action = nullptr;
  ink_assert(server_entry == nullptr);

  // ua_entry can be null if a scheduled update is also a reverse proxy
  // request. Added REVPROXY to the assert below, and then changed checks
  // to be based on ua_txn != NULL instead of req_flavor value.
  ink_assert(ua_entry != nullptr || t_state.req_flavor == HttpTransact::REQ_FLAVOR_SCHEDULED_UPDATE ||
             t_state.req_flavor == HttpTransact::REQ_FLAVOR_REVPROXY);

  ink_assert(pending_action == nullptr);

  if (false == t_state.api_server_addr_set) {
    ink_assert(t_state.current.server->dst_addr.host_order_port() > 0);
  } else {
    ink_assert(t_state.current.server->dst_addr.port() != 0); // verify the plugin set it to something.
  }

  char addrbuf[INET6_ADDRPORTSTRLEN];
  SMDebug("http", "[%" PRId64 "] open connection to %s: %s", sm_id, t_state.current.server->name,
          ats_ip_nptop(&t_state.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));

  SMDebug("http_seq", "[L4rSM::do_http_server_open] Sending request to server");

  milestones[TS_MILESTONE_SERVER_CONNECT] = Thread::get_hrtime();
  if (milestones[TS_MILESTONE_SERVER_FIRST_CONNECT] == 0) {
    milestones[TS_MILESTONE_SERVER_FIRST_CONNECT] = milestones[TS_MILESTONE_SERVER_CONNECT];
  }

  // If this is not a raw connection, we try to get a session from the
  //  shared session pool.  Raw connections are for SSLs tunnel and
  //  require a new connection
  //

  // This problem with POST requests is a bug.  Because of the issue of the
  // race with us sending a request after server has closed but before the FIN
  // gets to us, we should open a new connection for POST.  I believe TS used
  // to do this but as far I can tell the code that prevented keep-alive if
  // there is a request body has been removed.

  // If we are sending authorizations headers, mark the connection private
  //
  // We do this here because it means that we will not waste a connection from the pool if we already
  // know that the session will be private. This is overridable meaning that if a plugin later decides
  // it shouldn't be private it can still be returned to a shared pool.
  //

  // If there is already an attached server session mark it as private.
  if (server_session != nullptr && will_be_private_ss) {
    set_server_session_private(true);
  }

  // We did not manage to get an existing session
  //  and need to open a new connection
  Action *connect_action_handle;

  NetVCOptions opt;
  opt.f_blocking_connect = false;
  opt.set_sock_param(t_state.txn_conf->sock_recv_buffer_size_out, t_state.txn_conf->sock_send_buffer_size_out,
                     t_state.txn_conf->sock_option_flag_out, t_state.txn_conf->sock_packet_mark_out,
                     t_state.txn_conf->sock_packet_tos_out);

  opt.ip_family = ip_family;

  if (ua_txn) {
    opt.local_port = ua_txn->get_outbound_port();

    const IpAddr &outbound_ip = AF_INET6 == ip_family ? ua_txn->get_outbound_ip6() : ua_txn->get_outbound_ip4();
    if (outbound_ip.isValid()) {
      opt.addr_binding = NetVCOptions::INTF_ADDR;
      opt.local_ip     = outbound_ip;
    } else if (ua_txn->is_outbound_transparent()) {
      opt.addr_binding = NetVCOptions::FOREIGN_ADDR;
      opt.local_ip     = t_state.client_info.src_addr;
      /* If the connection is server side transparent, we can bind to the
         port that the client chose instead of randomly assigning one at
         the proxy.  This is controlled by the 'use_client_source_port'
         configuration parameter.
      */

      NetVConnection *client_vc = ua_txn->get_netvc();
      if (t_state.http_config_param->use_client_source_port && nullptr != client_vc) {
        opt.local_port = client_vc->get_remote_port();
      }
    }
  }

  // We will try this later if connect_s doesn't work
  //SMDebug("http", "calling netProcessor.connect_re");
  //connect_action_handle = netProcessor.connect_re(this,                                 // state machine
  //                                                &t_state.current.server->dst_addr.sa, // addr + port
  //                                                &opt);
  {
    // The request transform would be applied to POST and/or PUT request.
    // The server_vc should be established (writeable) before request transform start.
    // The CheckConnect is created by connect_s,
    //   It will callback NET_EVENT_OPEN to L4rSM if server_vc is WRITE_READY,
    //   Otherwise NET_EVENT_OPEN_FAILED is callbacked.
    MgmtInt connect_timeout;

    ink_assert(t_state.method == HTTP_WKSIDX_CONNECT || t_state.method == HTTP_WKSIDX_POST || t_state.method == HTTP_WKSIDX_PUT);

    // Set the inactivity timeout to the connect timeout so that we
    // we fail this server if it doesn't start sending the response
    // header
    connect_timeout = t_state.txn_conf->connect_attempts_timeout;

    SMDebug("http", "calling netProcessor.connect_s");
    connect_action_handle = netProcessor.connect_s(this,                                 // state machine
                                                   &t_state.current.server->dst_addr.sa, // addr + port
                                                   connect_timeout, &opt);
  }

  if (connect_action_handle != ACTION_RESULT_DONE) {
    ink_assert(!pending_action);
    pending_action = connect_action_handle;
  }

  return;
}

void
L4rSM::do_api_callout_internal()
{
  if (t_state.backdoor_request) {
    handle_api_return();
    return;
  }

  switch (t_state.api_next_action) {
  case HttpTransact::SM_ACTION_API_SM_START:
    cur_hook_id = TS_HTTP_TXN_START_HOOK;
    break;
  case HttpTransact::SM_ACTION_API_PRE_REMAP:
    cur_hook_id = TS_HTTP_PRE_REMAP_HOOK;
    break;
  case HttpTransact::SM_ACTION_API_POST_REMAP:
    cur_hook_id = TS_HTTP_POST_REMAP_HOOK;
    break;
  case HttpTransact::SM_ACTION_API_READ_REQUEST_HDR:
    cur_hook_id = TS_HTTP_READ_REQUEST_HDR_HOOK;
    break;
  case HttpTransact::SM_ACTION_REQUEST_BUFFER_READ_COMPLETE:
    cur_hook_id = TS_HTTP_REQUEST_BUFFER_READ_COMPLETE_HOOK;
    break;
  case HttpTransact::SM_ACTION_API_OS_DNS:
    cur_hook_id = TS_HTTP_OS_DNS_HOOK;
    break;
  case HttpTransact::SM_ACTION_API_SEND_REQUEST_HDR:
    cur_hook_id = TS_HTTP_SEND_REQUEST_HDR_HOOK;
    break;
  case HttpTransact::SM_ACTION_API_READ_CACHE_HDR:
    cur_hook_id = TS_HTTP_READ_CACHE_HDR_HOOK;
    break;
  case HttpTransact::SM_ACTION_API_CACHE_LOOKUP_COMPLETE:
    cur_hook_id = TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK;
    break;
  case HttpTransact::SM_ACTION_API_READ_RESPONSE_HDR:
    cur_hook_id = TS_HTTP_READ_RESPONSE_HDR_HOOK;
    break;
  case HttpTransact::SM_ACTION_API_SEND_RESPONSE_HDR:
    cur_hook_id                             = TS_HTTP_SEND_RESPONSE_HDR_HOOK;
    milestones[TS_MILESTONE_UA_BEGIN_WRITE] = Thread::get_hrtime();
    break;
  case HttpTransact::SM_ACTION_API_SM_SHUTDOWN:
    if (callout_state == HTTP_API_IN_CALLOUT || callout_state == HTTP_API_DEFERED_SERVER_ERROR) {
      callout_state = HTTP_API_DEFERED_CLOSE;
      return;
    } else {
      cur_hook_id = TS_HTTP_TXN_CLOSE_HOOK;
    }
    break;
  default:
    cur_hook_id = (TSHttpHookID)-1;
    ink_assert(!"not reached");
  }

  cur_hook  = nullptr;
  cur_hooks = 0;
  state_api_callout(0, nullptr);
}

void
L4rSM::mark_host_failure(HostDBInfo *info, time_t time_down)
{
  char addrbuf[INET6_ADDRPORTSTRLEN];

  if (info->app.http_data.last_failure == 0) {
    char *url_str = t_state.hdr_info.client_request.url_string_get(&t_state.arena, nullptr);
    Log::error("CONNECT: could not connect to %s "
               "for '%s' (setting last failure time) connect_result=%d",
               ats_ip_ntop(&t_state.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)), url_str ? url_str : "<none>",
               t_state.current.server->connect_result);

    if (url_str) {
      t_state.arena.str_free(url_str);
    }
  }

  info->app.http_data.last_failure = time_down;

#ifdef DEBUG
  ink_assert(ink_local_time() + t_state.txn_conf->down_server_timeout > time_down);
#endif

  SMDebug("http", "[%" PRId64 "] hostdb update marking IP: %s as down", sm_id,
          ats_ip_nptop(&t_state.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));
}

void
L4rSM::set_ua_abort(HttpTransact::AbortState_t ua_abort, int event)
{
  t_state.client_info.abort = ua_abort;

  switch (ua_abort) {
  case HttpTransact::ABORTED:
  case HttpTransact::MAYBE_ABORTED:
    // More detailed client side abort logging based on event
    switch (event) {
    case VC_EVENT_ERROR:
      t_state.squid_codes.log_code = SQUID_LOG_ERR_CLIENT_READ_ERROR;
      break;
    case VC_EVENT_EOS:
    case VC_EVENT_ACTIVE_TIMEOUT:     // Won't matter. Server will hangup
    case VC_EVENT_INACTIVITY_TIMEOUT: // Won't matter. Send back 408
    // Fall-through
    default:
      t_state.squid_codes.log_code = SQUID_LOG_ERR_CLIENT_ABORT;
      break;
    }
    break;
  default:
    // Handled here:
    // HttpTransact::ABORT_UNDEFINED, HttpTransact::DIDNOT_ABORT
    break;
  }

  // Set the connection attribute code for the client so that
  //   we log the client finish code correctly
  switch (event) {
  case VC_EVENT_ACTIVE_TIMEOUT:
    t_state.client_info.state = HttpTransact::ACTIVE_TIMEOUT;
    break;
  case VC_EVENT_INACTIVITY_TIMEOUT:
    t_state.client_info.state = HttpTransact::INACTIVE_TIMEOUT;
    break;
  case VC_EVENT_ERROR:
    t_state.client_info.state = HttpTransact::CONNECTION_ERROR;
    break;
  }
}

void
L4rSM::mark_server_down_on_client_abort()
{
  /////////////////////////////////////////////////////
  //  Check see if the client aborted because the    //
  //  origin server was too slow in sending the      //
  //  response header.  If so, mark that             //
  //  server as down so other clients won't try to   //
  //  for revalidation or select it from a round     //
  //  robin set                                      //
  //                                                 //
  //  Note: we do not want to mark parent            //
  //  proxies as down with this metric because       //
  //  that upstream proxy may be working but         //
  //  the actual origin server is one that is hung   //
  /////////////////////////////////////////////////////
  if (t_state.current.request_to == HttpTransact::ORIGIN_SERVER && t_state.hdr_info.request_content_length <= 0) {
    if (milestones[TS_MILESTONE_SERVER_FIRST_CONNECT] != 0 && milestones[TS_MILESTONE_SERVER_FIRST_READ] == 0) {
      // Check to see if client waited for the threshold
      //  to declare the origin server as down
      ink_hrtime wait = Thread::get_hrtime() - milestones[TS_MILESTONE_SERVER_FIRST_CONNECT];
      if (wait < 0) {
        wait = 0;
      }
      if (ink_hrtime_to_sec(wait) > t_state.txn_conf->client_abort_threshold) {
        t_state.current.server->set_connect_fail(ETIMEDOUT);
        do_hostdb_update_if_necessary();
      }
    }
  }
}

// void L4rSM::release_server_session()
//
//  Called when we are not tunneling a response from the
//   server.  If the session is keep alive, release it back to the
//   shared pool, otherwise close it
//
void
L4rSM::release_server_session(bool serve_from_cache)
{
  if (server_session == nullptr) {
    return;
  }

  if (TS_SERVER_SESSION_SHARING_MATCH_NONE != t_state.txn_conf->server_session_sharing_match && t_state.current.server != nullptr &&
      t_state.current.server->keep_alive == HTTP_KEEPALIVE && t_state.hdr_info.server_response.valid() &&
      t_state.hdr_info.server_request.valid() &&
      (t_state.hdr_info.server_response.status_get() == HTTP_STATUS_NOT_MODIFIED ||
       (t_state.hdr_info.server_request.method_get_wksidx() == HTTP_WKSIDX_HEAD &&
        t_state.www_auth_content != HttpTransact::CACHE_AUTH_NONE)) &&
      /*plugin_tunnel_type == HTTP_NO_PLUGIN_TUNNEL*/ 1) {
    HTTP_DECREMENT_DYN_STAT(http_current_server_transactions_stat);
    server_session->server_trans_stat--;
    server_session->attach_hostname(t_state.current.server->name);
    if (t_state.www_auth_content == HttpTransact::CACHE_AUTH_NONE || serve_from_cache == false) {
      // Must explicitly set the keep_alive_no_activity time before doing the release
      server_session->get_netvc()->set_inactivity_timeout(HRTIME_SECONDS(t_state.txn_conf->keep_alive_no_activity_timeout_out));
      server_session->release();
    } else {
      // an authenticated server connection - attach to the local client
      // we are serving from cache for the current transaction
      t_state.www_auth_content = HttpTransact::CACHE_AUTH_SERVE;
      ua_txn->attach_server_session(server_session, false);
    }
  } else {
    server_session->do_io_close();
  }

  ink_assert(server_entry->vc == server_session);
  server_entry->in_tunnel = true;
  vc_table.cleanup_entry(server_entry);
  server_entry   = nullptr;
  server_session = nullptr;
}

// void L4rSM::handle_http_server_open()
//
//   The server connection is now open.  If there is a POST or PUT,
//    we need setup a transform is there is one otherwise we need
//    to send the request header
//
void
L4rSM::handle_http_server_open()
{
  // if we were a queued request, we need to decrement the queue size-- as we got a connection
  if (t_state.origin_request_queued) {
    CryptoHash hostname_hash;
    CryptoContext().hash_immediate(hostname_hash, static_cast<const void *>(t_state.current.server->name),
                                   strlen(t_state.current.server->name));

    ConnectionCountQueue *waiting_connections = ConnectionCountQueue::getInstance();
    waiting_connections->incrementCount(t_state.current.server->dst_addr, hostname_hash,
                                        (TSServerSessionSharingMatchType)t_state.txn_conf->server_session_sharing_match, -1);
    // The request is now not queued. This is important if the request will ever retry, the t_state is re-used
    t_state.origin_request_queued = false;
  }

  // [bwyatt] applying per-transaction OS netVC options here
  //          IFF they differ from the netVC's current options.
  //          This should keep this from being redundant on a
  //          server session's first transaction.
  if (nullptr != server_session) {
    NetVConnection *vc = server_session->get_netvc();
    if (vc != nullptr && (vc->options.sockopt_flags != t_state.txn_conf->sock_option_flag_out ||
                          vc->options.packet_mark != t_state.txn_conf->sock_packet_mark_out ||
                          vc->options.packet_tos != t_state.txn_conf->sock_packet_tos_out ||
                          vc->options.clientVerificationFlag != t_state.txn_conf->ssl_client_verify_server)) {
      vc->options.sockopt_flags          = t_state.txn_conf->sock_option_flag_out;
      vc->options.packet_mark            = t_state.txn_conf->sock_packet_mark_out;
      vc->options.packet_tos             = t_state.txn_conf->sock_packet_tos_out;
      vc->options.clientVerificationFlag = t_state.txn_conf->ssl_client_verify_server;
      vc->apply_options();
    }
  }

  //int method = t_state.hdr_info.server_request.method_get_wksidx();
  //if (method != HTTP_WKSIDX_TRACE &&
  //    (t_state.hdr_info.request_content_length > 0 || t_state.client_info.transfer_encoding == HttpTransact::CHUNKED_ENCODING) &&
  //    do_post_transform_open()) {
  //  do_setup_post_tunnel(HTTP_TRANSFORM_VC);
  //  // Start up read response in parallel in case of early error response
  //  setup_server_read_response_header();
  //} else {
  //  setup_server_send_request_api();
  //}
}

// void L4rSM::handle_server_setup_error(int event, void* data)
//
//   Handles setting t_state.current.state and calling
//    Transact in between opening an origin server connection
//    and receiving the response header (in the case of the
//    POST, a post tunnel happens in between the sending
//    request header and reading the response header
//
void
L4rSM::handle_server_setup_error(int event, void *data)
{
  VIO *vio = (VIO *)data;
  ink_assert(vio != nullptr);

  STATE_ENTER(&L4rSM::handle_server_setup_error, event);

  // If there is POST or PUT tunnel wait for the tunnel
  //  to figure out that things have gone to hell
#if 0
  if (tunnel.is_tunnel_active()) {
    ink_assert(server_entry->read_vio == data || server_entry->write_vio == data);
    SMDebug("http",
            "[%" PRId64 "] [handle_server_setup_error] "
            "forwarding event %s to post tunnel",
            sm_id, HttpDebugNames::get_event_name(event));
    HttpTunnelConsumer *c = tunnel.get_consumer(server_entry->vc);
    // it is possible only user agent post->post transform is set up
    // this happened for Linux iocore where NET_EVENT_OPEN was returned
    // for a non-existing listening port. the hack is to pass the error
    // event for server connection to post_transform_info
    if (c == nullptr && post_transform_info.vc) {
      c = tunnel.get_consumer(post_transform_info.vc);
      // c->handler_state = HTTP_SM_TRANSFORM_FAIL;

      // No point in proceeding if there is no consumer
      // Do we need to do additional clean up in the c == NULL case?
      if (c != nullptr) {
        HttpTunnelProducer *ua_producer = c->producer;
        ink_assert(ua_entry->vc == ua_producer->vc);

        ua_entry->vc_handler = &L4rSM::state_watch_for_client_abort;
        ua_entry->read_vio   = ua_producer->vc->do_io_read(this, INT64_MAX, c->producer->read_buffer);
        ua_producer->vc->do_io_shutdown(IO_SHUTDOWN_READ);

        ua_producer->alive         = false;
        ua_producer->handler_state = HTTP_SM_POST_SERVER_FAIL;
        tunnel.handleEvent(VC_EVENT_ERROR, c->write_vio);
        return;
      }
    } else {
      // c could be null here as well
      if (c != nullptr) {
        tunnel.handleEvent(event, c->write_vio);
        return;
      }
    }
    // If there is no consumer, let the event pass through to shutdown
  } else {
    if (post_transform_info.vc) {
      HttpTunnelConsumer *c = tunnel.get_consumer(post_transform_info.vc);
      if (c && c->handler_state == HTTP_SM_TRANSFORM_OPEN) {
        vc_table.cleanup_entry(post_transform_info.entry);
        post_transform_info.entry = nullptr;
        tunnel.deallocate_buffers();
        tunnel.reset();
      }
    }
  }
#endif
  switch (event) {
  case VC_EVENT_EOS:
    t_state.current.state = HttpTransact::CONNECTION_CLOSED;
    break;
  case VC_EVENT_ERROR:
    t_state.current.state        = HttpTransact::CONNECTION_ERROR;
    t_state.cause_of_death_errno = server_session->get_netvc()->lerrno;
    break;
  case VC_EVENT_ACTIVE_TIMEOUT:
    t_state.current.state = HttpTransact::ACTIVE_TIMEOUT;
    break;

  case VC_EVENT_INACTIVITY_TIMEOUT:
    // If we're writing the request and get an inactivity timeout
    //   before any bytes are written, the connection to the
    //   server failed
    // In case of TIMEOUT, the iocore sends back
    // server_entry->read_vio instead of the write_vio
    if (server_entry->write_vio && server_entry->write_vio->nbytes > 0 && server_entry->write_vio->ndone == 0) {
      t_state.current.state = HttpTransact::CONNECTION_ERROR;
    } else {
      t_state.current.state = HttpTransact::INACTIVE_TIMEOUT;
    }
    break;
  default:
    ink_release_assert(0);
  }

  if (event == VC_EVENT_INACTIVITY_TIMEOUT || event == VC_EVENT_ERROR) {
    // Clean up the vc_table entry so any events in play to the timed out server vio
    // don't get handled.  The connection isn't there.
    if (server_entry) {
      ink_assert(server_entry->vc_type == HTTP_SERVER_VC);
      vc_table.cleanup_entry(server_entry);
      server_entry   = nullptr;
      server_session = nullptr;
    }
  }

  // Closedown server connection and deallocate buffers
  ink_assert(!server_entry || server_entry->in_tunnel == false);

  // if we are waiting on a plugin callout for
  //   HTTP_API_SEND_REQUEST_HDR defer calling transact until
  //   after we've finished processing the plugin callout
  switch (callout_state) {
  case HTTP_API_NO_CALLOUT:
    // Normal fast path case, no api callouts in progress
    break;
  case HTTP_API_IN_CALLOUT:
  case HTTP_API_DEFERED_SERVER_ERROR:
    // Callout in progress note that we are in deferring
    //   the server error
    callout_state = HTTP_API_DEFERED_SERVER_ERROR;
    return;
  case HTTP_API_DEFERED_CLOSE:
    // The user agent has shutdown killing the sm
    //   but we are stuck waiting for the server callout
    //   to finish so do nothing here.  We don't care
    //   about the server connection at this and are
    //   just waiting till we can execute the close hook
    return;
  default:
    ink_release_assert(0);
  }

  call_transact_and_set_next_state(HttpTransact::HandleResponse);
}

void
L4rSM::attach_server_session(HttpServerSession *s)
{
  lsm_release_assert(server_session == nullptr);
  lsm_release_assert(server_entry == nullptr);
  lsm_release_assert(s->state == HSS_ACTIVE);
  server_session        = s;
  server_transact_count = server_session->transact_count++;
  // Propagate the per client IP debugging
  if (ua_txn) {
    s->get_netvc()->control_flags.set_flags(get_cont_flags().get_flags());
  } else { // If there is no ua_txn no sense in continuing to attach the server session
    return;
  }

  // Set the mutex so that we have something to update
  //   stats with
  server_session->mutex = this->mutex;

  HTTP_INCREMENT_DYN_STAT(http_current_server_transactions_stat);
  ++s->server_trans_stat;

  // Record the VC in our table
  server_entry             = vc_table.new_entry();
  server_entry->vc         = server_session;
  server_entry->vc_type    = HTTP_SERVER_VC;
  server_entry->vc_handler = &L4rSM::state_send_server_request_header;

  // es - is this a concern here in L4rSM?  Does it belong somewhere else?
  // Get server and client connections
  UnixNetVConnection *server_vc = dynamic_cast<UnixNetVConnection *>(server_session->get_netvc());
  UnixNetVConnection *client_vc = (UnixNetVConnection *)(ua_txn->get_netvc());
  SSLNetVConnection *ssl_vc     = dynamic_cast<SSLNetVConnection *>(client_vc);

  // Verifying that the user agent and server sessions/transactions are operating on the same thread.
  ink_release_assert(!server_vc || !client_vc || server_vc->thread == client_vc->thread);
  bool associated_connection = false;
  if (server_vc) { // if server_vc isn't a PluginVC
    if (ssl_vc) {  // if incoming connection is SSL
      bool client_trace = ssl_vc->getSSLTrace();
      if (client_trace) {
        // get remote address and port to mark corresponding traces
        const sockaddr *remote_addr = ssl_vc->get_remote_addr();
        uint16_t remote_port        = ssl_vc->get_remote_port();
        server_vc->setOriginTrace(true);
        server_vc->setOriginTraceAddr(remote_addr);
        server_vc->setOriginTracePort(remote_port);
        associated_connection = true;
      }
    }
  }
  if (!associated_connection && server_vc) {
    server_vc->setOriginTrace(false);
    server_vc->setOriginTraceAddr(nullptr);
    server_vc->setOriginTracePort(0);
  }

  // set flag for server session is SSL
  SSLNetVConnection *server_ssl_vc = dynamic_cast<SSLNetVConnection *>(server_vc);
  if (server_ssl_vc) {
    server_connection_is_ssl = true;
  }

  // Initiate a read on the session so that the SM and not
  //  session manager will get called back if the timeout occurs
  //  or the server closes on us.  The IO Core now requires us to
  //  do the read with a buffer and a size so preallocate the
  //  buffer
  server_buffer_reader = server_session->get_reader();
  // ts-3189 We are only setting up an empty read at this point.  This
  // is sufficient to have the timeout errors directed to the appropriate
  // SM handler, but we don't want to read any data until the tunnel has
  // been set up.  This isn't such a big deal with GET results, since
  // if no tunnels are set up, there is no danger of data being delivered
  // to the wrong tunnel's consumer handler.  But for post and other
  // methods that send data after the request, two tunnels are created in
  // series, and with a full read set up at this point, the EOS from the
  // first tunnel was sometimes behind handled by the consumer of the
  // first tunnel instead of the producer of the second tunnel.
  // The real read is setup in setup_server_read_response_header()
  //
  server_entry->read_vio = server_session->do_io_read(this, 0, server_session->read_buffer);

  // Transfer control of the write side as well
  server_entry->write_vio = server_session->do_io_write(this, 0, nullptr);

  // Setup the timeouts
  // Set the inactivity timeout to the connect timeout so that we
  //   we fail this server if it doesn't start sending the response
  //   header
  MgmtInt connect_timeout;

  if (t_state.method == HTTP_WKSIDX_POST || t_state.method == HTTP_WKSIDX_PUT) {
    connect_timeout = t_state.txn_conf->post_connect_attempts_timeout;
  } else if (t_state.current.server == &t_state.parent_info) {
    connect_timeout = t_state.txn_conf->parent_connect_timeout;
  } else {
    connect_timeout = t_state.txn_conf->connect_attempts_timeout;
  }

  if (t_state.api_txn_connect_timeout_value != -1) {
    server_session->get_netvc()->set_inactivity_timeout(HRTIME_MSECONDS(t_state.api_txn_connect_timeout_value));
  } else {
    server_session->get_netvc()->set_inactivity_timeout(HRTIME_SECONDS(connect_timeout));
  }

  if (t_state.api_txn_active_timeout_value != -1) {
    server_session->get_netvc()->set_active_timeout(HRTIME_MSECONDS(t_state.api_txn_active_timeout_value));
  } else {
    server_session->get_netvc()->set_active_timeout(HRTIME_SECONDS(t_state.txn_conf->transaction_active_timeout_out));
  }

  if (/*plugin_tunnel_type != HTTP_NO_PLUGIN_TUNNEL || */will_be_private_ss) {
    SMDebug("http_ss", "Setting server session to private");
    set_server_session_private(true);
  }
}

//////////////////////////////////////////////////////////////////////////
//
//  L4rSM::setup_error_transfer()
//
//  The proxy has generated an error message which it
//  is sending to the client. For some cases, however,
//  such as when the proxy is transparent, returning
//  a proxy-generated error message exposes the proxy,
//  destroying transparency. The HttpBodyFactory code,
//  therefore, does not generate an error message body
//  in such cases. This function checks for the presence
//  of an error body. If its not present, it closes the
//  connection to the user, else it simply calls
//  setup_write_proxy_internal, which is the standard
//  routine for setting up proxy-generated responses.
//
//////////////////////////////////////////////////////////////////////////
void
L4rSM::setup_error_transfer()
{
  if (t_state.internal_msg_buffer || is_response_body_precluded(t_state.http_return_code)) {
    // Since we need to send the error message, call the API
    //   function
    ink_assert(t_state.internal_msg_buffer_size > 0 || is_response_body_precluded(t_state.http_return_code));
    t_state.api_next_action = HttpTransact::SM_ACTION_API_SEND_RESPONSE_HDR;
    do_api_callout();
  } else {
    SMDebug("http", "[setup_error_transfer] Now closing connection ...");
    vc_table.cleanup_entry(ua_entry);
    ua_entry = nullptr;
    // ua_txn     = NULL;
    terminate_sm   = true;
    t_state.source = HttpTransact::SOURCE_INTERNAL;
  }
}

void
L4rSM::setup_internal_transfer(L4rSMHandler handler_arg)
{
  bool is_msg_buf_present;

  if (t_state.internal_msg_buffer) {
    is_msg_buf_present = true;
    ink_assert(t_state.internal_msg_buffer_size > 0);

    // Set the content length here since a plugin
    //   may have changed the error body
    t_state.hdr_info.client_response.set_content_length(t_state.internal_msg_buffer_size);
    t_state.hdr_info.client_response.field_delete(MIME_FIELD_TRANSFER_ENCODING, MIME_LEN_TRANSFER_ENCODING);

    // set internal_msg_buffer_type if available
    if (t_state.internal_msg_buffer_type) {
      int len = strlen(t_state.internal_msg_buffer_type);

      if (len > 0) {
        t_state.hdr_info.client_response.value_set(MIME_FIELD_CONTENT_TYPE, MIME_LEN_CONTENT_TYPE, t_state.internal_msg_buffer_type,
                                                   len);
      }
      ats_free(t_state.internal_msg_buffer_type);
      t_state.internal_msg_buffer_type = nullptr;
    } else {
      t_state.hdr_info.client_response.value_set(MIME_FIELD_CONTENT_TYPE, MIME_LEN_CONTENT_TYPE, "text/html", 9);
    }
  } else {
    is_msg_buf_present = false;

    // If we are sending a response that can have a body
    //   but doesn't have a body add a content-length of zero.
    //   Needed for keep-alive on PURGE requests
    if (!is_response_body_precluded(t_state.hdr_info.client_response.status_get(), t_state.method)) {
      t_state.hdr_info.client_response.set_content_length(0);
      t_state.hdr_info.client_response.field_delete(MIME_FIELD_TRANSFER_ENCODING, MIME_LEN_TRANSFER_ENCODING);
    }
  }

  t_state.source = HttpTransact::SOURCE_INTERNAL;

  int64_t buf_size =
    index_to_buffer_size(HTTP_HEADER_BUFFER_SIZE_INDEX) + (is_msg_buf_present ? t_state.internal_msg_buffer_size : 0);

  MIOBuffer *buf            = new_MIOBuffer(buffer_size_to_index(buf_size));

  // First write the client response header into the buffer
  //client_response_hdr_bytes = write_response_header_into_buffer(&t_state.hdr_info.client_response, buf);
  int64_t nbytes            = client_response_hdr_bytes;

  // Next append the message onto the MIOBuffer

  // From HTTP/1.1 RFC:
  // "The HEAD method is identical to GET except that the server
  // MUST NOT return a message-body in the response. The metainformation
  // in the HTTP headers in response to a HEAD request SHOULD be
  // identical to the information sent in response to a GET request."
  // --> do not append the message onto the MIOBuffer and keep our pointer
  // to it so that it can be freed.

  if (is_msg_buf_present && t_state.method != HTTP_WKSIDX_HEAD) {
    nbytes += t_state.internal_msg_buffer_size;

    if (t_state.internal_msg_buffer_fast_allocator_size < 0) {
      buf->append_xmalloced(t_state.internal_msg_buffer, t_state.internal_msg_buffer_size);
    } else {
      buf->append_fast_allocated(t_state.internal_msg_buffer, t_state.internal_msg_buffer_size,
                                 t_state.internal_msg_buffer_fast_allocator_size);
    }

    // The IOBufferBlock will free the msg buffer when necessary so
    //  eliminate our pointer to it
    t_state.internal_msg_buffer      = nullptr;
    t_state.internal_msg_buffer_size = 0;
  }

  L4R_SM_SET_DEFAULT_HANDLER(handler_arg);

  // Clear the decks before we setup the new producers
  // As things stand, we cannot have two static producers operating at
  // once
  //tunnel.reset();

  // Setup the tunnel to the client
  //HttpTunnelProducer *p =
  //  tunnel.add_producer(HTTP_TUNNEL_STATIC_PRODUCER, nbytes, buf_start, (HttpProducerHandler) nullptr, HT_STATIC, "internal msg");
  //tunnel.add_consumer(ua_entry->vc, HTTP_TUNNEL_STATIC_PRODUCER, &L4rSM::tunnel_handler_ua, HT_HTTP_CLIENT, "user agent");

  //ua_entry->in_tunnel = true;
  //tunnel.tunnel_run(p);
}

// int L4rSM::find_http_resp_buffer_size(int cl)
//
//   Returns the allocation index for the buffer for
//     a response based on the content length
//
int
L4rSM::find_http_resp_buffer_size(int64_t content_length)
{
  int64_t buf_size;
  int64_t alloc_index;

  if (content_length == HTTP_UNDEFINED_CL) {
    // Try use our configured default size.  Otherwise pick
    //   the default size
    alloc_index = (int)t_state.txn_conf->default_buffer_size_index;
    if (alloc_index < MIN_CONFIG_BUFFER_SIZE_INDEX || alloc_index > DEFAULT_MAX_BUFFER_SIZE) {
      alloc_index = DEFAULT_RESPONSE_BUFFER_SIZE_INDEX;
    }
  } else {
#ifdef WRITE_AND_TRANSFER
    buf_size = HTTP_HEADER_BUFFER_SIZE + content_length - index_to_buffer_size(HTTP_SERVER_RESP_HDR_BUFFER_INDEX);
#else
    buf_size = index_to_buffer_size(HTTP_HEADER_BUFFER_SIZE_INDEX) + content_length;
#endif
    alloc_index = buffer_size_to_index(buf_size);
  }

  return alloc_index;
}

// int L4rSM::server_transfer_init()
//
//    Moves data from the header buffer into the reply buffer
//      and return the number of bytes we should use for initiating the
//      tunnel
//
int64_t
L4rSM::server_transfer_init(MIOBuffer *buf, int hdr_size)
{
  int64_t nbytes;
  int64_t to_copy = INT64_MAX;

  ink_assert(t_state.current.server != nullptr); // should have been set up if we're doing a transfer.

  if (server_entry->eos == true) {
    // The server has shutdown on us already so the only data
    //  we'll get is already in the buffer
    nbytes = server_buffer_reader->read_avail() + hdr_size;
  } else if (t_state.hdr_info.response_content_length == HTTP_UNDEFINED_CL) {
    nbytes = -1;
  } else {
    //  Set to copy to the number of bytes we want to write as
    //  if the server is sending us a bogus response we have to
    //  truncate it as we've already decided to trust the content
    //  length
    to_copy = t_state.hdr_info.response_content_length;
    nbytes  = t_state.hdr_info.response_content_length + hdr_size;
  }

  // Next order of business if copy the remaining data from the
  //  header buffer into new buffer.

  int64_t server_response_pre_read_bytes =
#ifdef WRITE_AND_TRANSFER
    /* relinquish the space in server_buffer and let
       the tunnel use the trailing space
     */
    buf->write_and_transfer_left_over_space(server_buffer_reader, to_copy);
#else
    buf->write(server_buffer_reader, to_copy);
#endif
  server_buffer_reader->consume(server_response_pre_read_bytes);

  //  If we know the length & copied the entire body
  //   of the document out of the header buffer make
  //   sure the server isn't screwing us by having sent too
  //   much.  If it did, we want to close the server connection
  if (server_response_pre_read_bytes == to_copy && server_buffer_reader->read_avail() > 0) {
    t_state.current.server->keep_alive = HTTP_NO_KEEPALIVE;
  }
#ifdef LAZY_BUF_ALLOC
  // reset the server session buffer
  server_session->reset_read_buffer();
#endif
  return nbytes;
}

//////////////////////////////////////////////////////////////////////////
//
//  L4rSM::kill_this()
//
//  This function has two phases.  One before we call the asynchronous
//    clean up routines (api and list removal) and one after.
//    The state about which phase we are in is kept in
//    L4rSM::kill_this_async_done
//
//////////////////////////////////////////////////////////////////////////
void
L4rSM::kill_this()
{
  ink_release_assert(reentrancy_count == 1);
  //this->postbuf_clear();
  //enable_redirection = false;

  if (kill_this_async_done == false) {
    ////////////////////////////////
    // cancel uncompleted actions //
    ////////////////////////////////
    // The action should be cancelled only if
    // the state machine is in HTTP_API_NO_CALLOUT
    // state. This is because we are depending on the
    // callout to complete for the state machine to
    // get killed.
    if (callout_state == HTTP_API_NO_CALLOUT && pending_action) {
      pending_action->cancel();
      pending_action = nullptr;
    } else if (pending_action) {
      ink_assert(pending_action == nullptr);
    }

    vc_table.cleanup_all();

    // tunnel.deallocate_buffers();
    // Why don't we just kill the tunnel?  Might still be
    // active if the state machine is going down hard,
    // and we should clean it up.
    //tunnel.kill_tunnel();

    // It possible that a plugin added transform hook
    //   but the hook never executed due to a client abort
    //   In that case, we need to manually close all the
    //   transforms to prevent memory leaks (INKqa06147)
    //if (hooks_set) {
    //  transform_cleanup(TS_HTTP_RESPONSE_TRANSFORM_HOOK, &transform_info);
    //  transform_cleanup(TS_HTTP_REQUEST_TRANSFORM_HOOK, &post_transform_info);
    //  plugin_agents_cleanup();
    //}
    // It's also possible that the plugin_tunnel vc was never
    //   executed due to not contacting the server
    //if (plugin_tunnel) {
    //  plugin_tunnel->kill_no_connect();
    //  plugin_tunnel = nullptr;
    //}

    server_session = nullptr;

    // So we don't try to nuke the state machine
    //  if the plugin receives event we must reset
    //  the terminate_flag
    terminate_sm            = false;
    t_state.api_next_action = HttpTransact::SM_ACTION_API_SM_SHUTDOWN;
    do_api_callout();
  }
  // The reentrancy_count is still valid up to this point since
  //   the api shutdown hook is asynchronous and double frees can
  //   happen if the reentrancy count is not still valid until
  //   after all asynch callouts have completed
  //
  // Once we get to this point, we could be waiting for async
  //   completion in which case we need to decrement the reentrancy
  //   count since the entry points can't do it for us since they
  //   don't know if the state machine has been destroyed.  In the
  //   case we really are done with asynch callouts, decrement the
  //   reentrancy count since it seems tacky to destruct a state
  //   machine with non-zero count
  reentrancy_count--;
  ink_release_assert(reentrancy_count == 0);

  // If the api shutdown & list removal was synchronous
  //   then the value of kill_this_async_done has changed so
  //   we must check it again
  if (kill_this_async_done == true) {
    ink_assert(pending_action == nullptr);
    if (t_state.http_config_param->enable_http_stats) {
      update_stats();
    }

    if (ua_txn) {
      ua_txn->transaction_done();
    }

    // In the async state, the plugin could have been
    // called resulting in the creation of a plugin_tunnel.
    // So it needs to be deleted now.
    //if (plugin_tunnel) {
    //  plugin_tunnel->kill_no_connect();
    //  plugin_tunnel = nullptr;
    //}

    ink_assert(pending_action == nullptr);
    ink_release_assert(vc_table.is_table_clear() == true);
    //ink_release_assert(tunnel.is_tunnel_active() == false);

    L4R_SM_SET_DEFAULT_HANDLER(nullptr);

    //////////////
    // Log Data //
    //////////////
    SMDebug("http_seq", "[L4rSM::update_stats] Logging transaction");
#if 0
    if (Log::transaction_logging_enabled() && t_state.api_info.logging_enabled) {
      LogAccessHttp accessor(this);

      int ret = Log::access(&accessor);

      if (ret & Log::FULL) {
        SMDebug("http", "[update_stats] Logging system indicates FULL.");
      }
      if (ret & Log::FAIL) {
        Log::error("failed to log transaction for at least one log object");
      }
    }

    if (redirect_url != nullptr) {
      ats_free((void *)redirect_url);
      redirect_url     = nullptr;
      redirect_url_len = 0;
    }
#endif

#ifdef USE_HTTP_DEBUG_LISTS
    ink_mutex_acquire(&debug_sm_list_mutex);
    debug_sm_list.remove(this);
    ink_mutex_release(&debug_sm_list_mutex);
#endif

    SMDebug("http", "[%" PRId64 "] deallocating sm", sm_id);
    //    authAdapter.destroyState();
    HTTP_DECREMENT_DYN_STAT(http_current_client_transactions_stat);
    destroy();
  }
}

void
L4rSM::update_stats()
{
  milestones[TS_MILESTONE_SM_FINISH] = Thread::get_hrtime();

  if (is_action_tag_set("bad_length_state_dump")) {
    if (t_state.hdr_info.client_response.valid() && t_state.hdr_info.client_response.status_get() == HTTP_STATUS_OK) {
      int64_t p_resp_cl = t_state.hdr_info.client_response.get_content_length();
      int64_t resp_size = client_response_body_bytes;
      if (!((p_resp_cl == -1 || p_resp_cl == resp_size || resp_size == 0))) {
        Error("[%" PRId64 "] Truncated content detected", sm_id);
        dump_state_on_assert();
      }
    } else if (client_request_hdr_bytes == 0) {
      Error("[%" PRId64 "] Zero length request header received", sm_id);
      dump_state_on_assert();
    }
  }

  if (is_action_tag_set("assert_jtest_length")) {
    if (t_state.hdr_info.client_response.valid() && t_state.hdr_info.client_response.status_get() == HTTP_STATUS_OK) {
      int64_t p_resp_cl = t_state.hdr_info.client_response.get_content_length();
      int64_t resp_size = client_response_body_bytes;
      ink_release_assert(p_resp_cl == -1 || p_resp_cl == resp_size || resp_size == 0);
    }
  }

  ink_hrtime total_time = milestones.elapsed(TS_MILESTONE_SM_START, TS_MILESTONE_SM_FINISH);

  // ua_close will not be assigned properly in some exceptional situation.
  // TODO: Assign ua_close with suitable value when HttpTunnel terminates abnormally.
  if (milestones[TS_MILESTONE_UA_CLOSE] == 0 && milestones[TS_MILESTONE_UA_READ_HEADER_DONE] > 0) {
    milestones[TS_MILESTONE_UA_CLOSE] = Thread::get_hrtime();
  }

  // request_process_time  = The time after the header is parsed to the completion of the transaction
  ink_hrtime request_process_time = milestones[TS_MILESTONE_UA_CLOSE] - milestones[TS_MILESTONE_UA_READ_HEADER_DONE];

  HttpTransact::client_result_stat(&t_state, total_time, request_process_time);

  ink_hrtime ua_write_time;
  if (milestones[TS_MILESTONE_UA_BEGIN_WRITE] != 0 && milestones[TS_MILESTONE_UA_CLOSE] != 0) {
    ua_write_time = milestones.elapsed(TS_MILESTONE_UA_BEGIN_WRITE, TS_MILESTONE_UA_CLOSE);
  } else {
    ua_write_time = -1;
  }

  ink_hrtime os_read_time;
  if (milestones[TS_MILESTONE_SERVER_READ_HEADER_DONE] != 0 && milestones[TS_MILESTONE_SERVER_CLOSE] != 0) {
    os_read_time = milestones.elapsed(TS_MILESTONE_SERVER_READ_HEADER_DONE, TS_MILESTONE_SERVER_CLOSE);
  } else {
    os_read_time = -1;
  }

  HttpTransact::update_size_and_time_stats(
    &t_state, total_time, ua_write_time, os_read_time, client_request_hdr_bytes, client_request_body_bytes,
    client_response_hdr_bytes, client_response_body_bytes, server_request_hdr_bytes, server_request_body_bytes,
    server_response_hdr_bytes, server_response_body_bytes, pushed_response_hdr_bytes, pushed_response_body_bytes, milestones);
  /*
      if (is_action_tag_set("http_handler_times")) {
          print_all_http_handler_times();
      }
  */

  // print slow requests if the threshold is set (> 0) and if we are over the time threshold
  if (t_state.txn_conf->slow_log_threshold != 0 && ink_hrtime_from_msec(t_state.txn_conf->slow_log_threshold) < total_time) {
    char url_string[256] = "";
    int offset           = 0;
    int skip             = 0;

    t_state.hdr_info.client_request.url_print(url_string, sizeof(url_string) - 1, &offset, &skip);
    url_string[offset] = 0; // NULL terminate the string

    // unique id
    char unique_id_string[128] = "";
    int length                 = 0;
    const char *field          = t_state.hdr_info.client_request.value_get(MIME_FIELD_X_ID, MIME_LEN_X_ID, &length);
    if (field != nullptr && length > 0) {
      length = std::min(length, static_cast<int>(sizeof(unique_id_string)) - 1);
      memcpy(unique_id_string, field, length);
      unique_id_string[length] = 0; // NULL terminate the string
    }

    // set the fd for the request
    int fd             = 0;
    NetVConnection *vc = nullptr;
    if (ua_txn != nullptr) {
      vc = ua_txn->get_netvc();
      if (vc != nullptr) {
        fd = vc->get_socket();
      } else {
        fd = -1;
      }
    }
    // get the status code, lame that we have to check to see if it is valid or we will assert in the method call
    int status = 0;
    if (t_state.hdr_info.client_response.valid()) {
      status = t_state.hdr_info.client_response.status_get();
    }
    char client_ip[INET6_ADDRSTRLEN];
    ats_ip_ntop(&t_state.client_info.src_addr, client_ip, sizeof(client_ip));
    Error("[%" PRId64 "] Slow Request: "
          "client_ip: %s:%u "
          "protocol: %s "
          "url: %s "
          "status: %d "
          "unique id: %s "
          "redirection_tries: %d "
          "bytes: %" PRId64 " "
          "fd: %d "
          "client state: %d "
          "server state: %d "
          "ua_begin: %.3f "
          "ua_first_read: %.3f "
          "ua_read_header_done: %.3f "
          "cache_open_read_begin: %.3f "
          "cache_open_read_end: %.3f "
          "dns_lookup_begin: %.3f "
          "dns_lookup_end: %.3f "
          "server_connect: %.3f "
          "server_connect_end: %.3f "
          "server_first_read: %.3f "
          "server_read_header_done: %.3f "
          "server_close: %.3f "
          "ua_write: %.3f "
          "ua_close: %.3f "
          "sm_finish: %.3f "
          "plugin_active: %.3f "
          "plugin_total: %.3f",
          sm_id, client_ip, t_state.client_info.src_addr.host_order_port(), ua_txn ? ua_txn->get_protocol_string() : "-1",
          url_string, status, unique_id_string, /*redirection_tries*/0, client_response_body_bytes, fd, t_state.client_info.state,
          t_state.server_info.state, milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_UA_BEGIN),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_UA_FIRST_READ),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_UA_READ_HEADER_DONE),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_CACHE_OPEN_READ_BEGIN),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_CACHE_OPEN_READ_END),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_DNS_LOOKUP_BEGIN),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_DNS_LOOKUP_END),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_SERVER_CONNECT),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_SERVER_CONNECT_END),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_SERVER_FIRST_READ),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_SERVER_READ_HEADER_DONE),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_SERVER_CLOSE),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_UA_BEGIN_WRITE),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_UA_CLOSE),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_SM_FINISH),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_PLUGIN_ACTIVE),
          milestones.difference_sec(TS_MILESTONE_SM_START, TS_MILESTONE_PLUGIN_TOTAL));
  }
}

//
// void L4rSM::dump_state_on_assert
//    Debugging routine to dump the state machine's history
//     and other state on an assertion failure
//    We use Diags::Status instead of stderr since
//     Diags works both on UNIX & NT
//
void
L4rSM::dump_state_on_assert()
{
  Error("[%" PRId64 "] ------- begin http state dump -------", sm_id);

  if (history.overflowed()) {
    Error("   History Wrap around. history size: %d", history.size());
  }
  // Loop through the history and dump it
  for (unsigned int i = 0; i < history.size(); i++) {
    char buf[256];
    int r = history[i].reentrancy;
    int e = history[i].event;
    Error("%d   %d   %s", e, r, history[i].location.str(buf, sizeof(buf)));
  }

  // Dump the via string
  Error("Via String: [%s]\n", t_state.via_string);

  Error("[%" PRId64 "] ------- end http state dump ---------", sm_id);
}

/*****************************************************************************
 *****************************************************************************
 ****                                                                     ****
 ****                       HttpTransact Interface                        ****
 ****                                                                     ****
 *****************************************************************************
 *****************************************************************************/
//////////////////////////////////////////////////////////////////////////
//
//      L4rSM::call_transact_and_set_next_state(f)
//
//      This routine takes an HttpTransact function <f>, calls the function
//      to perform some actions on the current HttpTransact::State, and
//      then uses the HttpTransact return action code to set the next
//      handler (state) for the state machine.  HttpTransact could have
//      returned the handler directly, but returns action codes in hopes of
//      making a cleaner separation between the state machine and the
//      HttpTransact logic.
//
//////////////////////////////////////////////////////////////////////////

// Where is the goatherd?

void
L4rSM::call_transact_and_set_next_state(TransactEntryFunc_t f)
{
  last_action = t_state.next_action; // remember where we were

  // The callee can either specify a method to call in to Transact,
  //   or call with NULL which indicates that Transact should use
  //   its stored entry point.
  if (f == nullptr) {
    ink_release_assert(t_state.transact_return_point != nullptr);
    t_state.transact_return_point(&t_state);
  } else {
    f(&t_state);
  }

  SMDebug("http", "[%" PRId64 "] State Transition: %s -> %s", sm_id, HttpDebugNames::get_action_name(last_action),
          HttpDebugNames::get_action_name(t_state.next_action));

  set_next_state();

  return;
}

//////////////////////////////////////////////////////////////////////////////
//
//  L4rSM::set_next_state()
//
//  call_transact_and_set_next_state() was broken into two parts, one
//  which calls the HttpTransact method and the second which sets the
//  next state. In a case which set_next_state() was not completed,
//  the state function calls set_next_state() to retry setting the
//  state.
//
//////////////////////////////////////////////////////////////////////////////
void
L4rSM::set_next_state()
{
  ///////////////////////////////////////////////////////////////////////
  // Use the returned "next action" code to set the next state handler //
  ///////////////////////////////////////////////////////////////////////
  switch (t_state.next_action) {
  case HttpTransact::SM_ACTION_REQUEST_BUFFER_READ_COMPLETE:
  case HttpTransact::SM_ACTION_API_OS_DNS:
  case HttpTransact::SM_ACTION_API_SEND_REQUEST_HDR: {
    t_state.api_next_action = t_state.next_action;
    do_api_callout();
    break;
  }

  case HttpTransact::SM_ACTION_POST_REMAP_SKIP: {
    call_transact_and_set_next_state(nullptr);
    break;
  }

  case HttpTransact::SM_ACTION_DNS_LOOKUP: {
    sockaddr const *addr;

    if (t_state.api_server_addr_set) {
      /* If the API has set the server address before the OS DNS lookup
       * then we can skip the lookup
       */
      ip_text_buffer ipb;
      SMDebug("dns", "[HttpTransact::HandleRequest] Skipping DNS lookup for API supplied target %s.",
              ats_ip_ntop(&t_state.server_info.dst_addr, ipb, sizeof(ipb)));
      // this seems wasteful as we will just copy it right back
      ats_ip_copy(t_state.host_db_info.ip(), &t_state.server_info.dst_addr);
      t_state.dns_info.lookup_success = true;
      call_transact_and_set_next_state(nullptr);
      break;
    } else if (0 == ats_ip_pton(t_state.dns_info.lookup_name, t_state.host_db_info.ip()) &&
               ats_is_ip_loopback(t_state.host_db_info.ip())) {
      // If it's 127.0.0.1 or ::1 don't bother with hostdb
      SMDebug("dns", "[HttpTransact::HandleRequest] Skipping DNS lookup for %s because it's loopback",
              t_state.dns_info.lookup_name);
      t_state.dns_info.lookup_success = true;
      call_transact_and_set_next_state(nullptr);
      break;
    } else if (t_state.http_config_param->use_client_target_addr == 2 && !t_state.url_remap_success &&
               t_state.parent_result.result != PARENT_SPECIFIED && t_state.client_info.is_transparent &&
               t_state.dns_info.os_addr_style == HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_DEFAULT &&
               ats_is_ip(addr = t_state.state_machine->ua_txn->get_netvc()->get_local_addr())) {
      /* If the connection is client side transparent and the URL
       * was not remapped/directed to parent proxy, we can use the
       * client destination IP address instead of doing a DNS
       * lookup. This is controlled by the 'use_client_target_addr'
       * configuration parameter.
       */
      if (is_debug_tag_set("dns")) {
        ip_text_buffer ipb;
        SMDebug("dns", "[HttpTransact::HandleRequest] Skipping DNS lookup for client supplied target %s.",
                ats_ip_ntop(addr, ipb, sizeof(ipb)));
      }
      ats_ip_copy(t_state.host_db_info.ip(), addr);
      if (t_state.hdr_info.client_request.version_get() == HTTPVersion(0, 9)) {
        t_state.host_db_info.app.http_data.http_version = HostDBApplicationInfo::HTTP_VERSION_09;
      } else if (t_state.hdr_info.client_request.version_get() == HTTPVersion(1, 0)) {
        t_state.host_db_info.app.http_data.http_version = HostDBApplicationInfo::HTTP_VERSION_10;
      } else {
        t_state.host_db_info.app.http_data.http_version = HostDBApplicationInfo::HTTP_VERSION_11;
      }

      t_state.dns_info.lookup_success = true;
      // cache this result so we don't have to unreliably duplicate the
      // logic later if the connect fails.
      t_state.dns_info.os_addr_style = HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_CLIENT;
      call_transact_and_set_next_state(nullptr);
      break;
    } else if (t_state.parent_result.result == PARENT_UNDEFINED && t_state.dns_info.lookup_success) {
      // Already set, and we don't have a parent proxy to lookup
      ink_assert(ats_is_ip(t_state.host_db_info.ip()));
      SMDebug("dns", "[HttpTransact::HandleRequest] Skipping DNS lookup, provided by plugin");
      call_transact_and_set_next_state(nullptr);
      break;
    } else if (t_state.dns_info.looking_up == HttpTransact::ORIGIN_SERVER && t_state.http_config_param->no_dns_forward_to_parent &&
               t_state.parent_result.result != PARENT_UNDEFINED) {
      t_state.dns_info.lookup_success = true;
      call_transact_and_set_next_state(nullptr);
      break;
    }

    L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::state_hostdb_lookup);

    // We need to close the previous attempt
    // Because it could be a server side retry by DNS rr
    if (server_entry) {
      ink_assert(server_entry->vc_type == HTTP_SERVER_VC);
      vc_table.cleanup_entry(server_entry);
      server_entry   = nullptr;
      server_session = nullptr;
    } else {
      // Now that we have gotten the user agent request, we can cancel
      // the inactivity timeout associated with it.  Note, however, that
      // we must not cancel the inactivity timeout if the message
      // contains a body (as indicated by the non-zero request_content_length
      // field).  This indicates that a POST operation is taking place and
      // that the client is still sending data to the origin server.  The
      // origin server cannot reply until the entire request is received.  In
      // light of this dependency, TS must ensure that the client finishes
      // sending its request and for this reason, the inactivity timeout
      // cannot be cancelled.
      if (ua_txn && !t_state.hdr_info.request_content_length) {
        ua_txn->cancel_inactivity_timeout();
      } else if (!ua_txn) {
        terminate_sm = true;
        return; // Give up if there is no session
      }
    }

    ink_assert(t_state.dns_info.looking_up != HttpTransact::UNDEFINED_LOOKUP);
    do_hostdb_lookup();
    break;
  }

  case HttpTransact::SM_ACTION_DNS_REVERSE_LOOKUP: {
    L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::state_hostdb_reverse_lookup);
    do_hostdb_reverse_lookup();
    break;
  }

  case HttpTransact::SM_ACTION_ORIGIN_SERVER_OPEN: {
    L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::state_http_server_open);

    // We need to close the previous attempt
    if (server_entry) {
      ink_assert(server_entry->vc_type == HTTP_SERVER_VC);
      vc_table.cleanup_entry(server_entry);
      server_entry   = nullptr;
      server_session = nullptr;
    } else {
      // Now that we have gotten the user agent request, we can cancel
      // the inactivity timeout associated with it.  Note, however, that
      // we must not cancel the inactivity timeout if the message
      // contains a body (as indicated by the non-zero request_content_length
      // field).  This indicates that a POST operation is taking place and
      // that the client is still sending data to the origin server.  The
      // origin server cannot reply until the entire request is received.  In
      // light of this dependency, TS must ensure that the client finishes
      // sending its request and for this reason, the inactivity timeout
      // cannot be cancelled.
      if (ua_txn && !t_state.hdr_info.request_content_length) {
        ua_txn->cancel_inactivity_timeout();
      } else if (!ua_txn) {
        terminate_sm = true;
        return; // Give up if there is no session
      }
    }

    do_http_server_open();
    break;
  }

  case HttpTransact::SM_ACTION_SERVER_READ: {
    t_state.source = HttpTransact::SOURCE_HTTP_ORIGIN_SERVER;

    {
      ink_assert((t_state.hdr_info.client_response.valid() ? true : false) == true);
      t_state.api_next_action = HttpTransact::SM_ACTION_API_SEND_RESPONSE_HDR;

      // check to see if we are going to handle the redirection from server response and if there is a plugin hook set
      if (hooks_set) {
        do_api_callout_internal();
      }
    }
    break;
  }

  case HttpTransact::SM_ACTION_ORIGIN_SERVER_RR_MARK_DOWN: {
    L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::state_mark_os_down);

    ink_assert(t_state.dns_info.looking_up == HttpTransact::ORIGIN_SERVER);

    // TODO: This might not be optimal (or perhaps even correct), but it will
    // effectively mark the host as down. What's odd is that state_mark_os_down
    // above isn't triggering.
    L4rSM::do_hostdb_update_if_necessary();

    do_hostdb_lookup();
    break;
  }

  case HttpTransact::SM_ACTION_SSL_TUNNEL: {
    t_state.api_next_action = HttpTransact::SM_ACTION_API_SEND_RESPONSE_HDR;
    do_api_callout();
    break;
  }

  case HttpTransact::SM_ACTION_ORIGIN_SERVER_RAW_OPEN: {
    L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::state_raw_http_server_open);

    ink_assert(server_entry == nullptr);
    do_http_server_open(true);
    break;
  }

  case HttpTransact::SM_ACTION_CONTINUE: {
    ink_release_assert(!"Not implemented");
    break;
  }

  case HttpTransact::SM_ACTION_UNDEFINED:
  default: {
    ink_release_assert("!Unknown next action");
  }
  }
}

void
L4rSM::set_http_schedule(Continuation *contp)
{
  L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::get_http_schedule);
  schedule_cont = contp;
}

int
L4rSM::get_http_schedule(int event, void * /* data ATS_UNUSED */)
{
  bool plugin_lock;
  Ptr<ProxyMutex> plugin_mutex;
  if (schedule_cont->mutex) {
    plugin_mutex = schedule_cont->mutex;
    plugin_lock  = MUTEX_TAKE_TRY_LOCK(schedule_cont->mutex, mutex->thread_holding);

    if (!plugin_lock) {
      L4R_SM_SET_DEFAULT_HANDLER(&L4rSM::get_http_schedule);
      ink_assert(pending_action == nullptr);
      pending_action = mutex->thread_holding->schedule_in(this, HRTIME_MSECONDS(10));
      return 0;
    } else {
      pending_action = nullptr; // if there was a pending action, it'll get freed after this returns so clear it.
    }
  } else {
    plugin_lock = false;
  }

  // handle Mutex;
  schedule_cont->handleEvent(event, this);
  if (plugin_lock) {
    Mutex_unlock(plugin_mutex, mutex->thread_holding);
  }

  return 0;
}

bool
L4rSM::set_server_session_private(bool private_session)
{
  if (server_session != nullptr) {
    server_session->private_session = private_session;
    return true;
  }
  return false;
}

inline bool
L4rSM::is_private()
{
  bool res = false;
  if (server_session) {
    res = server_session->private_session;
  } else if (ua_txn) {
    HttpServerSession *ss = ua_txn->get_server_session();
    if (ss) {
      res = ss->private_session;
    } else if (will_be_private_ss) {
      res = will_be_private_ss;
    }
  }
  return res;
}

// Fill in the client protocols used.  Return the number of entries returned
int
L4rSM::populate_client_protocol(std::string_view *result, int n) const
{
  int retval = 0;
  if (n > 0) {
    std::string_view proto = L4rSM::find_proto_string(t_state.hdr_info.client_request.version_get());
    if (!proto.empty()) {
      result[retval++] = proto;
      if (n > retval && ua_txn) {
        retval += ua_txn->populate_protocol(result + retval, n - retval);
      }
    }
  }
  return retval;
}

// Look for a specific protocol
const char *
L4rSM::client_protocol_contains(std::string_view tag_prefix) const
{
  const char *retval     = nullptr;
  std::string_view proto = L4rSM::find_proto_string(t_state.hdr_info.client_request.version_get());
  if (!proto.empty()) {
    std::string_view prefix(tag_prefix);
    if (prefix.size() <= proto.size() && 0 == strncmp(proto.data(), prefix.data(), prefix.size())) {
      retval = proto.data();
    } else if (ua_txn) {
      retval = ua_txn->protocol_contains(prefix);
    }
  }
  return retval;
}

std::string_view
L4rSM::find_proto_string(HTTPVersion version) const
{
  if (version == HTTPVersion(1, 1)) {
    return IP_PROTO_TAG_HTTP_1_1;
  } else if (version == HTTPVersion(1, 0)) {
    return IP_PROTO_TAG_HTTP_1_0;
  } else if (version == HTTPVersion(0, 9)) {
    return IP_PROTO_TAG_HTTP_0_9;
  }
  return {};
}

int
L4rSM::tunnel_handler_ssl_producer(int event, L4rTunnelProducer *p)
{
  STATE_ENTER(&L4rSM::tunnel_handler_ssl_producer, event);

  switch (event) {
  case VC_EVENT_EOS:
    // The write side of this connection is still alive
    //  so half-close the read
    if (p->self_consumer->alive) {
      p->vc->do_io_shutdown(IO_SHUTDOWN_READ);
      tunnel.local_finish_all(p);
      break;
    }
  // FALL THROUGH - both sides of the tunnel are dea
  case VC_EVENT_ERROR:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT:
    // The other side of the connection is either already dead
    //   or rendered inoperative by the error on the connection
    //   Note: use tunnel close vc so the tunnel knows we are
    //    nuking the of the connection as well
    tunnel.close_vc(p);
    tunnel.local_finish_all(p);

    // Because we've closed the net vc this error came in, it's write
    //  direction is now dead as well.  If that side still being fed data,
    //  we need to kill that pipe as well
    if (p->self_consumer->producer->alive) {
      p->self_consumer->producer->alive = false;
      if (p->self_consumer->producer->self_consumer->alive) {
        p->self_consumer->producer->vc->do_io_shutdown(IO_SHUTDOWN_READ);
      } else {
        tunnel.close_vc(p->self_consumer->producer);
      }
    }
    break;
  case VC_EVENT_READ_COMPLETE:
  case HTTP_TUNNEL_EVENT_PRECOMPLETE:
  // We should never get these event since we don't know
  //  how long the stream is
  default:
    ink_release_assert(0);
  }

  // Update stats
  switch (p->vc_type) {
  case HT_HTTP_SERVER:
    server_response_body_bytes += p->bytes_read;
    break;
  case HT_HTTP_CLIENT:
    client_request_body_bytes += p->bytes_read;
    break;
  default:
    // Covered here:
    // HT_CACHE_READ, HT_CACHE_WRITE,
    // HT_TRANSFORM, HT_STATIC.
    break;
  }

  return 0;
}

int
L4rSM::tunnel_handler_ssl_consumer(int event, L4rTunnelConsumer *c)
{
  STATE_ENTER(&L4rSM::tunnel_handler_ssl_consumer, event);

  switch (event) {
  case VC_EVENT_ERROR:
  case VC_EVENT_EOS:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT:
    // we need to mark the producer dead
    // otherwise it can stay alive forever.
    if (c->producer->alive) {
      c->producer->alive = false;
      if (c->producer->self_consumer->alive) {
        c->producer->vc->do_io_shutdown(IO_SHUTDOWN_READ);
      } else {
        tunnel.close_vc(c->producer);
      }
    }
    // Since we are changing the state of the self_producer
    //  we must have the tunnel shutdown the vc
    tunnel.close_vc(c);
    tunnel.local_finish_all(c->self_producer);
    break;

  case VC_EVENT_WRITE_COMPLETE:
    // If we get this event, it means that the producer
    //  has finished and we wrote the remaining data
    //  to the consumer
    //
    // If the read side of this connection has not yet
    //  closed, do a write half-close and then wait for
    //  read side to close so that we don't cut off
    //  pipelined responses with TCP resets
    //
    // ink_assert(c->producer->alive == false);
    c->write_success = true;
    if (c->self_producer->alive == true) {
      c->vc->do_io_shutdown(IO_SHUTDOWN_WRITE);
    } else {
      c->vc->do_io_close();
    }
    break;

  default:
    ink_release_assert(0);
  }

  // Update stats
  switch (c->vc_type) {
  case HT_HTTP_SERVER:
    server_request_body_bytes += c->bytes_written;
    break;
  case HT_HTTP_CLIENT:
    client_response_body_bytes += c->bytes_written;
    break;
  default:
    // Handled here:
    // HT_CACHE_READ, HT_CACHE_WRITE, HT_TRANSFORM,
    // HT_STATIC
    break;
  }

  return 0;
}

int
L4rSM::tunnel_handler(int event, void *data)
{
  STATE_ENTER(&L4rSM::tunnel_handler, event);

  ink_assert(event == HTTP_TUNNEL_EVENT_DONE);
  // The tunnel calls this when it is done
  terminate_sm = true;

  return 0;
}

