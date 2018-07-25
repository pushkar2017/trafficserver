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

   L4rTunnel.h

   Description:


****************************************************************************/

#pragma once

#include "ts/ink_platform.h"
#include "P_EventSystem.h"
#include "HttpSM.h"

// Get rid of any previous definition first... /leif
#ifdef MAX_PRODUCERS
#undef MAX_PRODUCERS
#endif
#ifdef MAX_CONSUMERS
#undef MAX_CONSUMERS
#endif
#define MAX_PRODUCERS 2
#define MAX_CONSUMERS 4

#define HTTP_TUNNEL_EVENT_DONE (HTTP_TUNNEL_EVENTS_START + 1)
#define HTTP_TUNNEL_EVENT_PRECOMPLETE (HTTP_TUNNEL_EVENTS_START + 2)
#define HTTP_TUNNEL_EVENT_CONSUMER_DETACH (HTTP_TUNNEL_EVENTS_START + 3)

#define HTTP_TUNNEL_STATIC_PRODUCER (VConnection *)!0

// YTS Team, yamsat Plugin
#define ALLOCATE_AND_WRITE_TO_BUF 1
#define WRITE_TO_BUF 2

struct L4rTunnelProducer;
class L4rSM;
class HttpPagesHandler;
typedef int (L4rSM::*L4rSMHandler)(int event, void *data);

struct L4rTunnelConsumer;
struct L4rTunnelProducer;
typedef int (L4rSM::*L4rProducerHandler)(int event, L4rTunnelProducer *p);
typedef int (L4rSM::*L4rConsumerHandler)(int event, L4rTunnelConsumer *c);

enum L4rTunnelType_t { L4R_SERVER, L4R_CLIENT, L4R_STATIC, L4R_BUFFER_READ };
struct L4rTunnelConsumer {
  L4rTunnelConsumer();

  LINK(L4rTunnelConsumer, link);
  L4rTunnelProducer *producer;
  L4rTunnelProducer *self_producer;

  L4rTunnelType_t vc_type;
  VConnection *vc;
  IOBufferReader *buffer_reader;
  L4rConsumerHandler vc_handler;
  VIO *write_vio;

  int64_t skip_bytes;    // bytes to skip at beginning of stream
  int64_t bytes_written; // total bytes written to the vc
  int handler_state;     // state used the handlers

  bool alive;
  bool write_success;
  const char *name;

  /** Check if this consumer is downstream from @a vc.
      @return @c true if any producer in the tunnel eventually feeds
      data to this consumer.
  */
  bool is_downstream_from(VConnection *vc);
  /** Check if this is a sink (final data destination).
      @return @c true if data exits the ATS process at this consumer.
  */
  bool is_sink() const;
};

struct L4rTunnelProducer {
  L4rTunnelProducer();

  DLL<L4rTunnelConsumer> consumer_list;
  L4rTunnelConsumer *self_consumer;
  VConnection *vc;
  L4rProducerHandler vc_handler;
  VIO *read_vio;
  MIOBuffer *read_buffer;
  IOBufferReader *buffer_start;
  L4rTunnelType_t vc_type;

  int64_t init_bytes_done; // bytes passed in buffer
  int64_t nbytes;          // total bytes (client's perspective)
  int64_t ntodo;           // what this vc needs to do
  int64_t bytes_read;      // total bytes read from the vc
  int handler_state;       // state used the handlers
  int last_event;          ///< Tracking for flow control restarts.

  int num_consumers;

  bool alive;
  bool read_success;
  /// Flag and pointer for active flow control throttling.
  /// If this is set, it points at the source producer that is under flow control.
  /// If @c NULL then data flow is not being throttled.
  L4rTunnelProducer *flow_control_source;
  const char *name;

  /** Get the largest number of bytes any consumer has not consumed.
      Use @a limit if you only need to check if the backlog is at least @a limit.
      @return The actual backlog or a number at least @a limit.
   */
  uint64_t backlog(uint64_t limit = UINT64_MAX ///< More than this is irrelevant
  );
  /// Check if producer is original (to ATS) source of data.
  /// @return @c true if this producer is the source of bytes from outside ATS.
  bool is_source() const;
  /// Throttle the flow.
  void throttle();
  /// Unthrottle the flow.
  void unthrottle();
  /// Check throttled state.
  bool is_throttled() const;

  /// Update the handler_state member if it is still 0
  void update_state_if_not_set(int new_handler_state);

  /** Set the flow control source producer for the flow.
      This sets the value for this producer and all downstream producers.
      @note This is the implementation for @c throttle and @c unthrottle.
      @see throttle
      @see unthrottle
  */
  void set_throttle_src(L4rTunnelProducer *srcp ///< Source producer of flow.
  );
};

class L4rTunnel : public Continuation
{
  friend class HttpPagesHandler;
  friend class CoreUtils;

  /** Data for implementing flow control across a tunnel.

      The goal is to bound the amount of data buffered for a
      transaction flowing through the tunnel to (roughly) between the
      @a high_water and @a low_water water marks. Due to the chunky nater of data
      flow this always approximate.
  */
  struct FlowControl {
    // Default value for high and low water marks.
    static uint64_t const DEFAULT_WATER_MARK = 1 << 16;

    uint64_t high_water; ///< Buffered data limit - throttle if more than this.
    uint64_t low_water;  ///< Unthrottle if less than this buffered.
    bool enabled_p;      ///< Flow control state (@c false means disabled).

    /// Default constructor.
    FlowControl();
  };

public:
  L4rTunnel();

  void init(L4rSM *sm_arg, Ptr<ProxyMutex> &amutex);
  void reset();
  void kill_tunnel();
  bool
  is_tunnel_active() const
  {
    return active;
  }
  bool is_tunnel_alive() const;

  L4rTunnelProducer *add_producer(VConnection *vc, int64_t nbytes, IOBufferReader *reader_start, L4rProducerHandler sm_handler,
                                   L4rTunnelType_t vc_type, const char *name);

  L4rTunnelConsumer *add_consumer(VConnection *vc, VConnection *producer, L4rConsumerHandler sm_handler, L4rTunnelType_t vc_type,
                                   const char *name, int64_t skip_bytes = 0);

  int deallocate_buffers();
  DLL<L4rTunnelConsumer> *get_consumers(VConnection *vc);
  L4rTunnelProducer *get_producer(VConnection *vc);
  L4rTunnelConsumer *get_consumer(VConnection *vc);
  L4rTunnelProducer *get_producer(L4rTunnelType_t type);
  void tunnel_run(L4rTunnelProducer *p = nullptr);

  int main_handler(int event, void *data);
  void consumer_reenable(L4rTunnelConsumer *c);
  bool consumer_handler(int event, L4rTunnelConsumer *c);
  bool producer_handler(int event, L4rTunnelProducer *p);
  void local_finish_all(L4rTunnelProducer *p);
  void chain_finish_all(L4rTunnelProducer *p);
  void chain_abort_all(L4rTunnelProducer *p);
  void append_message_to_producer_buffer(L4rTunnelProducer *p, const char *msg, int64_t msg_len);

  /** Mark a producer and consumer as the same underlying object.

      This is use to chain producer/consumer pairs together to
      indicate the data flows through them sequentially. The primary
      example is a transform which serves as a consumer on the server
      side and a producer on the cache/client side.
  */
  void chain(L4rTunnelConsumer *c, ///< Flow goes in here
             L4rTunnelProducer *p  ///< Flow comes back out here
  );

  void close_vc(L4rTunnelProducer *p);
  void close_vc(L4rTunnelConsumer *c);

private:
  void internal_error();
  void finish_all_internal(L4rTunnelProducer *p, bool chain);
  void update_stats_after_abort(L4rTunnelType_t t);
  void producer_run(L4rTunnelProducer *p);

  L4rTunnelProducer *get_producer(VIO *vio);
  L4rTunnelConsumer *get_consumer(VIO *vio);

  L4rTunnelProducer *alloc_producer();
  L4rTunnelConsumer *alloc_consumer();

  int num_producers = 0;
  int num_consumers = 0;
  L4rTunnelConsumer consumers[MAX_CONSUMERS];
  L4rTunnelProducer producers[MAX_PRODUCERS];
  L4rSM *sm = nullptr;

  bool active = false;

  /// State data about flow control.
  FlowControl flow_state;

private:
  int reentrancy_count = 0;
  bool call_sm         = false;
};

// void L4rTunnel::local_finish_all(L4rTunnelProducer* p)
//
//   After the producer has finished, causes direct consumers
//      to finish their writes
//
inline void
L4rTunnel::local_finish_all(L4rTunnelProducer *p)
{
  finish_all_internal(p, false);
}

// void L4rTunnel::chain_finish_all(L4rTunnelProducer* p)
//
//   After the producer has finished, cause everyone
//    downstream in the tunnel to send everything
//    that producer has placed in the buffer
//
inline void
L4rTunnel::chain_finish_all(L4rTunnelProducer *p)
{
  finish_all_internal(p, true);
}

inline bool
L4rTunnel::is_tunnel_alive() const
{
  bool tunnel_alive = false;

  for (const auto &producer : producers) {
    if (producer.alive == true) {
      tunnel_alive = true;
      break;
    }
  }
  if (!tunnel_alive) {
    for (const auto &consumer : consumers) {
      if (consumer.alive == true) {
        tunnel_alive = true;
        break;
      }
    }
  }

  return tunnel_alive;
}

inline L4rTunnelProducer *
L4rTunnel::get_producer(VConnection *vc)
{
  for (int i = 0; i < MAX_PRODUCERS; i++) {
    if (producers[i].vc == vc) {
      return producers + i;
    }
  }
  return nullptr;
}

inline L4rTunnelProducer *
L4rTunnel::get_producer(L4rTunnelType_t type)
{
  for (int i = 0; i < MAX_PRODUCERS; i++) {
    if (producers[i].vc_type == type) {
      return producers + i;
    }
  }
  return nullptr;
}

inline L4rTunnelConsumer *
L4rTunnel::get_consumer(VConnection *vc)
{
  /** Rare but persistent problem in which a @c INKVConnInternal is used by a consumer, released,
      and then re-allocated for a different consumer. This causes two consumers to have the same VC
      pointer resulting in this method returning the wrong consumer. Note this is a not a bad use of
      the tunnel, but an unfortunate interaction with the FIFO free lists.

      It's not correct to check for the consumer being alive - at a minimum `HTTP_TUNNEL_EVENT_DONE`
      is dispatched against a consumer after the consumer is not alive. Instead if a non-alive
      consumer matches it is stored as a candidate and returned if no other match is found. If a
      live matching consumer is found, it is immediately returned. It is never valid to have the
      same VC in more than one active consumer. This should avoid a performance impact because in
      the usual case the consumer will be alive.

      In the case of a deliberate dispatch of an event to a dead consumer that has a duplicate vc
      address, this will select the last consumer which will be correct as the consumers are added
      in order therefore the latter consumer will be the most recent / appropriate target.
  */
  L4rTunnelConsumer *zret = nullptr;
  for (L4rTunnelConsumer &c : consumers) {
    if (c.vc == vc) {
      zret = &c;
      if (c.alive) { // a match that's alive is always the best.
        break;
      }
    }
  }
  return zret;
}

inline L4rTunnelProducer *
L4rTunnel::get_producer(VIO *vio)
{
  for (int i = 0; i < MAX_PRODUCERS; i++) {
    if (producers[i].read_vio == vio) {
      return producers + i;
    }
  }
  return nullptr;
}

inline L4rTunnelConsumer *
L4rTunnel::get_consumer(VIO *vio)
{
  if (vio) {
    for (int i = 0; i < MAX_CONSUMERS; i++) {
      if (consumers[i].alive && (consumers[i].write_vio == vio || consumers[i].vc == vio->vc_server)) {
        return consumers + i;
      }
    }
  }
  return nullptr;
}

inline void
L4rTunnel::append_message_to_producer_buffer(L4rTunnelProducer *p, const char *msg, int64_t msg_len)
{
  if (p == nullptr || p->read_buffer == nullptr) {
    return;
  }

  p->read_buffer->write(msg, msg_len);
  p->nbytes += msg_len;
  p->bytes_read += msg_len;
}

inline bool
L4rTunnelConsumer::is_downstream_from(VConnection *vc)
{
  L4rTunnelProducer *p = producer;
  L4rTunnelConsumer *c;
  while (p) {
    if (p->vc == vc) {
      return true;
    }
    // The producer / consumer chain can contain a cycle in the case
    // of a blind tunnel so give up if we find ourself (the original
    // consumer).
    c = p->self_consumer;
    p = (c && c != this) ? c->producer : nullptr;
  }
  return false;
}

inline bool
L4rTunnelConsumer::is_sink() const
{
  return L4R_CLIENT == vc_type;
}

inline bool
L4rTunnelProducer::is_source() const
{
  // If a producer is marked as a client, then it's part of a bidirectional tunnel
  // and so is an actual source of data.
  return L4R_SERVER == vc_type || L4R_CLIENT == vc_type;
}

inline void
L4rTunnelProducer::update_state_if_not_set(int new_handler_state)
{
  if (this->handler_state == 0) {
    this->handler_state = new_handler_state;
  }
}

inline bool
L4rTunnelProducer::is_throttled() const
{
  return nullptr != flow_control_source;
}

inline void
L4rTunnelProducer::throttle()
{
  if (!this->is_throttled()) {
    this->set_throttle_src(this);
  }
}

inline void
L4rTunnelProducer::unthrottle()
{
  if (this->is_throttled()) {
    this->set_throttle_src(nullptr);
  }
}

inline L4rTunnel::FlowControl::FlowControl() : high_water(DEFAULT_WATER_MARK), low_water(DEFAULT_WATER_MARK), enabled_p(false) {}
