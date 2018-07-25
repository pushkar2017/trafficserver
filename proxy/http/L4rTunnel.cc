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

   L4rTunnel.cc

   Description:


****************************************************************************/

#include "ts/ink_config.h"
#include "HttpConfig.h"
#include "L4rTunnel.h"
#include "L4rSM.h"
#include "HttpDebugNames.h"
#include "ts/ParseRules.h"

static const int min_block_transfer_bytes = 256;
L4rTunnelProducer::L4rTunnelProducer()
  : consumer_list(),
    self_consumer(nullptr),
    vc(nullptr),
    vc_handler(nullptr),
    read_vio(nullptr),
    read_buffer(nullptr),
    buffer_start(nullptr),
    vc_type(L4R_SERVER),
    init_bytes_done(0),
    nbytes(0),
    ntodo(0),
    bytes_read(0),
    handler_state(0),
    last_event(0),
    num_consumers(0),
    alive(false),
    read_success(false),
    flow_control_source(nullptr),
    name(nullptr)
{
}

uint64_t
L4rTunnelProducer::backlog(uint64_t limit)
{
  uint64_t zret = 0;
  // Calculate the total backlog, the # of bytes inside ATS for this producer.
  // We go all the way through each chain to the ending sink and take the maximum
  // over those paths. Do need to be careful about loops which can occur.
  for (L4rTunnelConsumer *c = consumer_list.head; c; c = c->link.next) {
    if (c->alive && c->write_vio) {
      uint64_t n = 0;
      IOBufferReader *r = c->write_vio->get_reader();
      if (r) {
        n += static_cast<uint64_t>(r->read_avail());
      }
      if (n >= limit) {
        return n;
      }

      if (!c->is_sink()) {
        L4rTunnelProducer *dsp = c->self_producer;
        if (dsp) {
          n += dsp->backlog();
        }
      }
      if (n >= limit) {
        return n;
      }
      if (n > zret) {
        zret = n;
      }
    }
  }

  return zret;
}

/*  We set the producers in a flow chain specifically rather than
    using a tunnel level variable in order to handle bi-directional
    tunnels correctly. In such a case the flow control on producers is
    not related so a single value for the tunnel won't work.
*/
void
L4rTunnelProducer::set_throttle_src(L4rTunnelProducer *srcp)
{
  L4rTunnelProducer *p  = this;
  p->flow_control_source = srcp;
  for (L4rTunnelConsumer *c = consumer_list.head; c; c = c->link.next) {
    if (!c->is_sink()) {
      p = c->self_producer;
      if (p) {
        p->set_throttle_src(srcp);
      }
    }
  }
}

L4rTunnelConsumer::L4rTunnelConsumer()
  : link(),
    producer(nullptr),
    self_producer(nullptr),
    vc_type(L4R_CLIENT),
    vc(nullptr),
    buffer_reader(nullptr),
    vc_handler(nullptr),
    write_vio(nullptr),
    skip_bytes(0),
    bytes_written(0),
    handler_state(0),
    alive(false),
    write_success(false),
    name(nullptr)
{
}

L4rTunnel::L4rTunnel() : Continuation(nullptr) {}

void
L4rTunnel::init(L4rSM *sm_arg, Ptr<ProxyMutex> &amutex)
{
  HttpConfigParams *params = sm_arg->t_state.http_config_param;
  sm                       = sm_arg;
  active                   = false;
  mutex                    = amutex;
  ink_release_assert(reentrancy_count == 0);
  SET_HANDLER(&L4rTunnel::main_handler);
  flow_state.enabled_p = params->oride.flow_control_enabled;
  if (params->oride.flow_low_water_mark > 0) {
    flow_state.low_water = params->oride.flow_low_water_mark;
  }
  if (params->oride.flow_high_water_mark > 0) {
    flow_state.high_water = params->oride.flow_high_water_mark;
  }
  // This should always be true, we handled default cases back in HttpConfig::reconfigure()
  ink_assert(flow_state.low_water <= flow_state.high_water);
}

void
L4rTunnel::reset()
{
  ink_assert(active == false);
#ifdef DEBUG
  for (int i = 0; i < MAX_PRODUCERS; ++i) {
    ink_assert(producers[i].alive == false);
  }
  for (int j = 0; j < MAX_CONSUMERS; ++j) {
    ink_assert(consumers[j].alive == false);
  }
#endif

  num_producers = 0;
  num_consumers = 0;
  memset(consumers, 0, sizeof(consumers));
  memset(producers, 0, sizeof(producers));
}

void
L4rTunnel::kill_tunnel()
{
  for (auto &producer : producers) {
    if (producer.vc != nullptr) {
      chain_abort_all(&producer);
    }
    ink_assert(producer.alive == false);
  }
  active = false;
  this->deallocate_buffers();
  this->reset();
}

L4rTunnelProducer *
L4rTunnel::alloc_producer()
{
  for (int i = 0; i < MAX_PRODUCERS; ++i) {
    if (producers[i].vc == nullptr) {
      num_producers++;
      ink_assert(num_producers <= MAX_PRODUCERS);
      return producers + i;
    }
  }
  ink_release_assert(0);
  return nullptr;
}

L4rTunnelConsumer *
L4rTunnel::alloc_consumer()
{
  for (int i = 0; i < MAX_CONSUMERS; i++) {
    if (consumers[i].vc == nullptr) {
      num_consumers++;
      ink_assert(num_consumers <= MAX_CONSUMERS);
      return consumers + i;
    }
  }
  ink_release_assert(0);
  return nullptr;
}

int
L4rTunnel::deallocate_buffers()
{
  int num = 0;
  ink_release_assert(active == false);
  for (auto &producer : producers) {
    if (producer.read_buffer != nullptr) {
      ink_assert(producer.vc != nullptr);
      free_MIOBuffer(producer.read_buffer);
      producer.read_buffer  = nullptr;
      producer.buffer_start = nullptr;
      num++;
    }

  }
  return num;
}

// L4rTunnelProducer* L4rTunnel::add_producer
//
//   Adds a new producer to the tunnel
//
L4rTunnelProducer *
L4rTunnel::add_producer(VConnection *vc, int64_t nbytes_arg, IOBufferReader *reader_start, L4rProducerHandler sm_handler,
                         L4rTunnelType_t vc_type, const char *name_arg)
{
  L4rTunnelProducer *p;

  Debug("l4r_tunnel", "[%" PRId64 "] adding producer '%s'", sm->sm_id, name_arg);

  ink_assert(reader_start->mbuf);
  if ((p = alloc_producer()) != nullptr) {
    p->vc              = vc;
    p->nbytes          = nbytes_arg;
    p->buffer_start    = reader_start;
    p->read_buffer     = reader_start->mbuf;
    p->vc_handler      = sm_handler;
    p->vc_type         = vc_type;
    p->name            = name_arg;

    p->init_bytes_done = reader_start->read_avail();
    if (p->nbytes < 0) {
      p->ntodo = p->nbytes;
    } else { // The byte count given us includes bytes
      //  that alread may be in the buffer.
      //  ntodo represents the number of bytes
      //  the tunneling mechanism needs to read
      //  for the producer
      p->ntodo = p->nbytes - p->init_bytes_done;
      ink_assert(p->ntodo >= 0);
    }

    // We are static, the producer is never "alive"
    //   It just has data in the buffer
    if (vc == HTTP_TUNNEL_STATIC_PRODUCER) {
      ink_assert(p->ntodo == 0);
      p->alive        = false;
      p->read_success = true;
    } else {
      p->alive = true;
    }
  }
  return p;
}

// void L4rTunnel::add_consumer
//
//    Adds a new consumer to the tunnel.  The producer must
//    be specified and already added to the tunnel.  Attaches
//    the new consumer to the entry for the existing producer
//
//    Returns true if the consumer successfully added.  Returns
//    false if the consumer was not added because the source failed
//
L4rTunnelConsumer *
L4rTunnel::add_consumer(VConnection *vc, VConnection *producer, L4rConsumerHandler sm_handler, L4rTunnelType_t vc_type,
                         const char *name_arg, int64_t skip_bytes)
{
  Debug("l4r_tunnel", "[%" PRId64 "] adding consumer '%s'", sm->sm_id, name_arg);

  // Find the producer entry
  L4rTunnelProducer *p = get_producer(producer);
  ink_release_assert(p);

  // Check to see if the producer terminated
  //  without sending all of its data
  if (p->alive == false && p->read_success == false) {
    Debug("l4r_tunnel", "[%" PRId64 "] consumer '%s' not added due to producer failure", sm->sm_id, name_arg);
    return nullptr;
  }
  // Initialize the consumer structure
  L4rTunnelConsumer *c = alloc_consumer();
  c->producer           = p;
  c->vc                 = vc;
  c->alive              = true;
  c->skip_bytes         = skip_bytes;
  c->vc_handler         = sm_handler;
  c->vc_type            = vc_type;
  c->name               = name_arg;

  // Register the consumer with the producer
  p->consumer_list.push(c);
  p->num_consumers++;

  return c;
}

void
L4rTunnel::chain(L4rTunnelConsumer *c, L4rTunnelProducer *p)
{
  p->self_consumer = c;
  c->self_producer = p;
  // If the flow is already throttled update the chained producer.
  if (c->producer->is_throttled()) {
    p->set_throttle_src(c->producer->flow_control_source);
  }
}

// void L4rTunnel::tunnel_run()
//
//    Makes the tunnel go
//
void
L4rTunnel::tunnel_run(L4rTunnelProducer *p_arg)
{
  Debug("l4r_tunnel", "tunnel_run started, p_arg is %s", p_arg ? "provided" : "NULL");
  if (p_arg) {
    producer_run(p_arg);
  } else {
    L4rTunnelProducer *p;

    ink_assert(active == false);

    for (int i = 0; i < MAX_PRODUCERS; ++i) {
      p = producers + i;
      if (p->vc != nullptr && (p->alive || (p->vc_type == L4R_STATIC && p->buffer_start != nullptr))) {
        producer_run(p);
      }
    }
  }

  // It is possible that there was nothing to do
  //   due to a all transfers being zero length
  //   If that is the case, call the state machine
  //   back to say we are done
  if (!is_tunnel_alive()) {
    active = false;
    sm->handleEvent(HTTP_TUNNEL_EVENT_DONE, this);
  }
}

void
L4rTunnel::producer_run(L4rTunnelProducer *p)
{
  // Determine whether the producer has a cache-write consumer,
  // since all chunked content read by the producer gets dechunked
  // prior to being written into the cache.
  L4rTunnelConsumer *c;

  int64_t consumer_n;
  int64_t producer_n;

  ink_assert(p->vc != nullptr);
  active = true;

  int64_t read_start_pos = 0;
  if (p->nbytes >= 0) {
    consumer_n = p->nbytes;
    producer_n = p->ntodo;
  } else {
    consumer_n = (producer_n = INT64_MAX);
  }

  // Do the IO on the consumers first so
  //  data doesn't disappear out from
  //  under the tunnel
  for (c = p->consumer_list.head; c;) {
    // Create a reader for each consumer.  The reader allows
    // us to implement skip bytes
    // Non-cache consumers.
    {
      c->buffer_reader = p->read_buffer->clone_reader(p->buffer_start);
    }

    // Consume bytes of the reader if we skipping bytes
    if (c->skip_bytes > 0) {
      ink_assert(c->skip_bytes <= c->buffer_reader->read_avail());
      c->buffer_reader->consume(c->skip_bytes);
    }
    int64_t c_write = consumer_n;

    // INKqa05109 - if we don't know the length leave it at
    //  INT64_MAX or else the cache may bounce the write
    //  because it thinks the document is too big.  INT64_MAX
    //  is a special case for the max document size code
    //  in the cache
    if (c_write != INT64_MAX) {
      c_write -= c->skip_bytes;
    }

    if (c_write == 0) {
      // Nothing to do, call back the cleanup handlers
      c->write_vio = nullptr;
      consumer_handler(VC_EVENT_WRITE_COMPLETE, c);
    } else {
      // In the client half close case, all the data that will be sent
      // from the client is already in the buffer.  Go ahead and set
      // the amount to read since we know it.  We will forward the FIN
      // to the server on VC_EVENT_WRITE_COMPLETE.
      if (p->vc_type == L4R_CLIENT) {
        ProxyClientTransaction *ua_vc = static_cast<ProxyClientTransaction *>(p->vc);
        if (ua_vc->get_half_close_flag()) {
          c_write          = c->buffer_reader->read_avail();
          p->alive         = false;
          p->handler_state = HTTP_SM_POST_SUCCESS;
        }
      }
      c->write_vio = c->vc->do_io_write(this, c_write, c->buffer_reader);
      ink_assert(c_write > 0);
    }

    c = c->link.next;
  }

  producer_handler(VC_EVENT_READ_READY, p);

  if (p->alive) {
    ink_assert(producer_n >= 0);

    if (producer_n == 0) {
      // Everything is already in the buffer so mark the producer as done.  We need to notify
      // state machine that everything is done.  We use a special event to say the producers is
      // done but we didn't do anything
      p->alive         = false;
      p->read_success  = true;
      p->handler_state = HTTP_SM_POST_SUCCESS;
      Debug("l4r_tunnel", "[%" PRId64 "] [tunnel_run] producer already done", sm->sm_id);
      producer_handler(HTTP_TUNNEL_EVENT_PRECOMPLETE, p);
    } else {
      if (read_start_pos > 0) {
        p->read_vio = ((CacheVC *)p->vc)->do_io_pread(this, producer_n, p->read_buffer, read_start_pos);
      } else {
        p->read_vio = p->vc->do_io_read(this, producer_n, p->read_buffer);
      }
    }
  }

  // Now that the tunnel has started, we must remove producer's reader so
  // that it doesn't act like a buffer guard
  if (p->read_buffer && p->buffer_start) {
    p->read_buffer->dealloc_reader(p->buffer_start);
  }
  p->buffer_start = nullptr;
}

//
// bool L4rTunnel::producer_handler(int event, L4rTunnelProducer* p)
//
//   Handles events from producers.
//
//   If the event is interesting only to the tunnel, this
//    handler takes all necessary actions and returns false
//    If the event is interesting to the state_machine,
//    it calls back the state machine and returns true
//
//
bool
L4rTunnel::producer_handler(int event, L4rTunnelProducer *p)
{
  L4rTunnelConsumer *c;
  L4rProducerHandler jump_point;
  bool sm_callback = false;

  Debug("l4r_tunnel", "[%" PRId64 "] producer_handler [%s %s]", sm->sm_id, p->name, HttpDebugNames::get_event_name(event));

  p->last_event = event;

  // YTS Team, yamsat Plugin
  // Copy partial POST data to buffers. Check for the various parameters including
  // the maximum configured post data size

  Debug("http_redirect", "[L4rTunnel::producer_handler] enable_redirection: [%d %d %d] event: %d", p->alive == true,
        0, (p->self_consumer && p->self_consumer->alive == true), event);

  switch (event) {
  case VC_EVENT_READ_READY:
    // Data read from producer, reenable consumers
    for (c = p->consumer_list.head; c; c = c->link.next) {
      if (c->alive && c->write_vio) {
        c->write_vio->reenable();
      }
    }
    break;

  case HTTP_TUNNEL_EVENT_PRECOMPLETE:
    // If the write completes on the stack (as it can for http2), then
    // consumer could have called back by this point.  Must treat this as
    // a regular read complete (falling through to the following cases).

  case VC_EVENT_READ_COMPLETE:
  case VC_EVENT_EOS:
    // The producer completed
    p->alive = false;
    if (p->read_vio) {
      p->bytes_read = p->read_vio->ndone;
    } else {
      // If we are chunked, we can receive the whole document
      //   along with the header without knowing it (due to
      //   the message length being a property of the encoding)
      //   In that case, we won't have done a do_io so there
      //   will not be vio
      p->bytes_read = 0;
    }

    // callback the SM to notify of completion
    //  Note: we need to callback the SM before
    //  reenabling the consumers as the reenable may
    //  make the data visible to the consumer and
    //  initiate async I/O operation.  The SM needs to
    //  set how much I/O to do before async I/O is
    //  initiated
    jump_point = p->vc_handler;
    (sm->*jump_point)(event, p);
    sm_callback = true;
    p->update_state_if_not_set(HTTP_SM_POST_SUCCESS);

    // Data read from producer, reenable consumers
    for (c = p->consumer_list.head; c; c = c->link.next) {
      if (c->alive && c->write_vio) {
        c->write_vio->reenable();
      }
    }
    break;

  case VC_EVENT_ERROR:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case HTTP_TUNNEL_EVENT_CONSUMER_DETACH:
    if (p->alive) {
      p->alive      = false;
      p->bytes_read = p->read_vio->ndone;
      // Clear any outstanding reads so they don't
      // collide with future tunnel IO's
      p->vc->do_io_read(nullptr, 0, nullptr);
      // Interesting tunnel event, call SM
      jump_point = p->vc_handler;
      (sm->*jump_point)(event, p);
      sm_callback = true;
      // Failure case anyway
      p->update_state_if_not_set(HTTP_SM_POST_UA_FAIL);
    }
    break;

  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE:
  default:
    // Producers should not get these events
    ink_release_assert(0);
    break;
  }

  return sm_callback;
}

void
L4rTunnel::consumer_reenable(L4rTunnelConsumer *c)
{
  L4rTunnelProducer *p = c->producer;

  if (p && p->alive
#ifndef LAZY_BUF_ALLOC
      && p->read_buffer->write_avail() > 0
#endif
  ) {
    // Only do flow control if enabled and the producer is an external
    // source.  Otherwise disable by making the backlog zero. Because
    // the backlog short cuts quit when the value is equal (or
    // greater) to the target, we use strict comparison only for
    // checking low water, otherwise the flow control can stall out.
    uint64_t backlog         = (flow_state.enabled_p && p->is_source()) ? p->backlog(flow_state.high_water) : 0;
    L4rTunnelProducer *srcp = p->flow_control_source;

    if (backlog >= flow_state.high_water) {
      if (is_debug_tag_set("l4r_tunnel")) {
        Debug("l4r_tunnel", "Throttle   %p %" PRId64 " / %" PRId64, p, backlog, p->backlog());
      }
      p->throttle(); // p becomes srcp for future calls to this method
    } else {
      if (srcp && srcp->alive && c->is_sink()) {
        // Check if backlog is below low water - note we need to check
        // against the source producer, not necessarily the producer
        // for this consumer. We don't have to recompute the backlog
        // if they are the same because we know low water <= high
        // water so the value is sufficiently accurate.
        if (srcp != p) {
          backlog = srcp->backlog(flow_state.low_water);
        }
        if (backlog < flow_state.low_water) {
          if (is_debug_tag_set("l4r_tunnel")) {
            Debug("l4r_tunnel", "Unthrottle %p %" PRId64 " / %" PRId64, p, backlog, p->backlog());
          }
          srcp->unthrottle();
          if (srcp->read_vio) {
            srcp->read_vio->reenable();
          }
          // Kick source producer to get flow ... well, flowing.
          this->producer_handler(VC_EVENT_READ_READY, srcp);
        } else {
          // We can stall for small thresholds on network sinks because this event happens
          // before the actual socket write. So we trap for the buffer becoming empty to
          // make sure we get an event to unthrottle after the write.
          if (L4R_CLIENT == c->vc_type) {
            NetVConnection *netvc = dynamic_cast<NetVConnection *>(c->write_vio->vc_server);
            if (netvc) { // really, this should always be true.
              netvc->trapWriteBufferEmpty();
            }
          }
        }
      }
      if (p->read_vio) {
        p->read_vio->reenable();
      }
    }
  }
}

//
// bool L4rTunnel::consumer_handler(int event, L4rTunnelConsumer* p)
//
//   Handles events from consumers.
//
//   If the event is interesting only to the tunnel, this
//    handler takes all necessary actions and returns false
//    If the event is interesting to the state_machine,
//    it calls back the state machine and returns true
//
//
bool
L4rTunnel::consumer_handler(int event, L4rTunnelConsumer *c)
{
  bool sm_callback = false;
  L4rConsumerHandler jump_point;
  L4rTunnelProducer *p = c->producer;

  Debug("l4r_tunnel", "[%" PRId64 "] consumer_handler [%s %s]", sm->sm_id, c->name, HttpDebugNames::get_event_name(event));

  ink_assert(c->alive == true);

  switch (event) {
  case VC_EVENT_WRITE_READY:
    this->consumer_reenable(c);
    break;

  case VC_EVENT_WRITE_COMPLETE:
  case VC_EVENT_EOS:
  case VC_EVENT_ERROR:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
    ink_assert(c->alive);
    ink_assert(c->buffer_reader);
    c->alive = false;

    c->bytes_written = c->write_vio ? c->write_vio->ndone : 0;

    // Interesting tunnel event, call SM
    jump_point = c->vc_handler;
    (sm->*jump_point)(event, c);
    // Make sure the handler_state is set
    // Necessary for post tunnel end processing
    if (c->producer && c->producer->handler_state == 0) {
      if (event == VC_EVENT_WRITE_COMPLETE) {
        c->producer->handler_state = HTTP_SM_POST_SUCCESS;
      } else if (c->vc_type == L4R_SERVER) {
        c->producer->handler_state = HTTP_SM_POST_UA_FAIL;
      } else if (c->vc_type == L4R_CLIENT) {
        c->producer->handler_state = HTTP_SM_POST_SERVER_FAIL;
      }
    }
    sm_callback = true;

    // Deallocate the reader after calling back the sm
    //  because buffer problems are easier to debug
    //  in the sm when the reader is still valid
    if (c->buffer_reader) {
      c->buffer_reader->mbuf->dealloc_reader(c->buffer_reader);
      c->buffer_reader = nullptr;
    }

    // Since we removed a consumer, it may now be
    //   possbile to put more stuff in the buffer
    // Note: we reenable only after calling back
    //    the SM since the reenabling has the side effect
    //    updating the buffer state for the VConnection
    //    that is being reenabled
    if (p->alive && p->read_vio
#ifndef LAZY_BUF_ALLOC
        && p->read_buffer->write_avail() > 0
#endif
    ) {
      if (p->is_throttled()) {
        this->consumer_reenable(c);
      } else {
        p->read_vio->reenable();
      }
    }
    // [amc] I don't think this happens but we'll leave a debug trap
    // here just in case.
    if (p->is_throttled()) {
      Debug("l4r_tunnel", "Special event %s on %p with flow control on", HttpDebugNames::get_event_name(event), p);
    }
    break;

  case VC_EVENT_READ_READY:
  case VC_EVENT_READ_COMPLETE:
  default:
    // Consumers should not get these events
    ink_release_assert(0);
    break;
  }

  return sm_callback;
}

// void L4rTunnel::chain_abort_all(L4rTunnelProducer* p)
//
//    Abort the producer and everyone still alive
//     downstream of the producer
//
void
L4rTunnel::chain_abort_all(L4rTunnelProducer *p)
{
  L4rTunnelConsumer *c = p->consumer_list.head;

  while (c) {
    if (c->alive) {
      c->alive     = false;
      c->write_vio = nullptr;
      c->vc->do_io_close(EHTTP_ERROR);
      update_stats_after_abort(c->vc_type);
    }

    if (c->self_producer) {
      // Must snip the link before recursively
      // freeing to avoid looks introduced by
      // blind tunneling
      L4rTunnelProducer *selfp = c->self_producer;
      c->self_producer          = nullptr;
      chain_abort_all(selfp);
    }

    c = c->link.next;
  }

  if (p->alive) {
    p->alive = false;
    if (p->read_vio) {
      p->bytes_read = p->read_vio->ndone;
    }
    if (p->self_consumer) {
      p->self_consumer->alive = false;
    }
    p->read_vio = nullptr;
    p->vc->do_io_close(EHTTP_ERROR);
    update_stats_after_abort(p->vc_type);
  }
}

// void L4rTunnel::chain_finish_internal(L4rTunnelProducer* p)
//
//    Internal function for finishing all consumers.  Takes
//       chain argument about where to finish just immediate
//       consumer or all those downstream
//
void
L4rTunnel::finish_all_internal(L4rTunnelProducer *p, bool chain)
{
  ink_assert(p->alive == false);
  L4rTunnelConsumer *c         = p->consumer_list.head;
  int64_t total_bytes           = 0;

  while (c) {
    if (c->alive) {
      
      total_bytes = p->bytes_read + p->init_bytes_done;

      if (c->write_vio) {
        c->write_vio->nbytes = total_bytes - c->skip_bytes;
        ink_assert(c->write_vio->nbytes >= 0);

        if (c->write_vio->nbytes < 0) {
          // TODO: Wtf, printf?
          fprintf(stderr, "[L4rTunnel::finish_all_internal] ERROR: Incorrect total_bytes - c->skip_bytes = %" PRId64 "\n",
                  (int64_t)(total_bytes - c->skip_bytes));
        }
      }

      if (chain == true && c->self_producer) {
        chain_finish_all(c->self_producer);
      }
      // The IO Core will not call us back if there
      //   is nothing to do.  Check to see if there is
      //   nothing to do and take the appripriate
      //   action
      if (c->write_vio && c->write_vio->nbytes == c->write_vio->ndone) {
        consumer_handler(VC_EVENT_WRITE_COMPLETE, c);
      }
    }

    c = c->link.next;
  }
}

// void L4rTunnel::close_vc(L4rTunnelProducer* p)
//
//    Closes the vc associated with the producer and
//      updates the state of the self_consumer
//
void
L4rTunnel::close_vc(L4rTunnelProducer *p)
{
  ink_assert(p->alive == false);
  L4rTunnelConsumer *c = p->self_consumer;

  if (c && c->alive) {
    c->alive = false;
    if (c->write_vio) {
      c->bytes_written = c->write_vio->ndone;
    }
  }

  p->vc->do_io_close();
}

// void L4rTunnel::close_vc(L4rTunnelConsumer* c)
//
//    Closes the vc associated with the consumer and
//      updates the state of the self_producer
//
void
L4rTunnel::close_vc(L4rTunnelConsumer *c)
{
  ink_assert(c->alive == false);
  L4rTunnelProducer *p = c->self_producer;

  if (p && p->alive) {
    p->alive = false;
    if (p->read_vio) {
      p->bytes_read = p->read_vio->ndone;
    }
  }

  c->vc->do_io_close();
}

// int L4rTunnel::main_handler(int event, void* data)
//
//   Main handler for the tunnel.  Vectors events
//   based on whether they are from consumers or
//   producers
//
int
L4rTunnel::main_handler(int event, void *data)
{
  L4rTunnelProducer *p = nullptr;
  L4rTunnelConsumer *c = nullptr;
  bool sm_callback      = false;

  ++reentrancy_count;

  ink_assert(sm->magic == HTTP_SM_MAGIC_ALIVE);

  // Find the appropriate entry
  if ((p = get_producer((VIO *)data)) != nullptr) {
    sm_callback = producer_handler(event, p);
  } else {
    if ((c = get_consumer((VIO *)data)) != nullptr) {
      ink_assert(c->write_vio == (VIO *)data || c->vc == ((VIO *)data)->vc_server);
      sm_callback = consumer_handler(event, c);
    } else {
      internal_error(); // do nothing
    }
  }

  // We called a vc handler, the tunnel might be
  //  finished.  Check to see if there are any remaining
  //  VConnections alive.  If not, notifiy the state machine
  //
  // Don't call out if we are nested
  if (call_sm || (sm_callback && !is_tunnel_alive())) {
    if (reentrancy_count == 1) {
      reentrancy_count = 0;
      active           = false;
      sm->handleEvent(HTTP_TUNNEL_EVENT_DONE, this);
      return EVENT_DONE;
    } else {
      call_sm = true;
    }
  }
  --reentrancy_count;
  return EVENT_CONT;
}

void
L4rTunnel::update_stats_after_abort(L4rTunnelType_t t)
{
}

void
L4rTunnel::internal_error()
{
}
