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

#pragma once

#include "ts/ink_platform.h"
#include "records/I_RecHttp.h"
#include "P_EventSystem.h"
//#include "HttpConfig.h"
//#include "HTTP.h"
#include "I_Net.h"
#include <records/I_RecHttp.h>

namespace detail
{
/** Options for @c L4RSessionAccept.

    @internal This is done as a separate class for two reasons.

    The first is that in current usage many instances are created
    with the same options so (for the client) this is easier and
    more efficient than passing options directly to the @c
    L4RSessionAccept or calling setters.

    The second is that @c L4RSessionAccept is not provided with any thread
    safety because it is intended as an immutable object. Putting
    the setters here and not there makes that clearer.

    We don't do this directly as nested class because we want to
    inherit the data members rather than duplicate the declarations
    and initializations.
 */
class L4RSessionAcceptOptions
{
private:
  typedef L4RSessionAcceptOptions self; ///< Self reference type.
public:
  L4RSessionAcceptOptions();

  // Connection type (HttpProxyPort::TransportType)
  int transport_type;
  /// Set the transport type.
  self &setTransportType(int);
  /// Local address to bind for outbound connections.
  IpAddr outbound_ip4;
  /// Local address to bind for outbound connections.
  IpAddr outbound_ip6;
  /// Set the outbound IP address to @a ip.
  self &setOutboundIp(IpAddr &ip);
  /// Set the outbound IP address to @a ip.
  self &setOutboundIp(IpEndpoint *ip);
  /// Local port for outbound connection.
  uint16_t outbound_port;
  /// Set outbound port.
  self &setOutboundPort(uint16_t);
  /// Outbound transparent.
  bool f_outbound_transparent;
  /// Set outbound transparency.
  self &setOutboundTransparent(bool);
  /// Transparent pass-through.
  bool f_transparent_passthrough;
  /// Set transparent passthrough.
  self &setTransparentPassthrough(bool);
  /// Accepting backdoor connections.
  bool backdoor;
  /// Set backdoor accept.
  self &setBackdoor(bool);
  /// Host address resolution preference order.
  HostResPreferenceOrder host_res_preference;
  /// Set the host query preference.
  self &setHostResPreference(HostResPreferenceOrder const);
  /// Acceptable session protocols.
  SessionProtocolSet session_protocol_preference;
  /// Set the session protocol preference.
  self &setSessionProtocolPreference(SessionProtocolSet const &);
};

inline L4RSessionAcceptOptions::L4RSessionAcceptOptions()
  : transport_type(0), outbound_port(0), f_outbound_transparent(false), f_transparent_passthrough(false), backdoor(false)
{
  memcpy(host_res_preference, host_res_default_preference_order, sizeof(host_res_preference));
}

inline L4RSessionAcceptOptions &
L4RSessionAcceptOptions::setTransportType(int type)
{
  transport_type = type;
  return *this;
}

inline L4RSessionAcceptOptions &
L4RSessionAcceptOptions::setOutboundIp(IpAddr &ip)
{
  if (ip.isIp4())
    outbound_ip4 = ip;
  else if (ip.isIp6())
    outbound_ip6 = ip;
  return *this;
}

inline L4RSessionAcceptOptions &
L4RSessionAcceptOptions::setOutboundIp(IpEndpoint *ip)
{
  if (ip->isIp4())
    outbound_ip4 = *ip;
  else if (ip->isIp6())
    outbound_ip6 = *ip;
  return *this;
}

inline L4RSessionAcceptOptions &
L4RSessionAcceptOptions::setOutboundPort(uint16_t port)
{
  outbound_port = port;
  return *this;
}

inline L4RSessionAcceptOptions &
L4RSessionAcceptOptions::setOutboundTransparent(bool flag)
{
  f_outbound_transparent = flag;
  return *this;
}

inline L4RSessionAcceptOptions &
L4RSessionAcceptOptions::setTransparentPassthrough(bool flag)
{
  f_transparent_passthrough = flag;
  return *this;
}

inline L4RSessionAcceptOptions &
L4RSessionAcceptOptions::setBackdoor(bool flag)
{
  backdoor = flag;
  return *this;
}

inline L4RSessionAcceptOptions &
L4RSessionAcceptOptions::setHostResPreference(HostResPreferenceOrder const order)
{
  memcpy(host_res_preference, order, sizeof(host_res_preference));
  return *this;
}

inline L4RSessionAcceptOptions &
L4RSessionAcceptOptions::setSessionProtocolPreference(SessionProtocolSet const &sp_set)
{
  session_protocol_preference = sp_set;
  return *this;
}
} // namespace detail

/**
   The continuation mutex is NULL to allow parellel accepts in NT. No
   state is recorded by the handler and values are required to be set
   during construction via the @c Options struct and never changed. So
   a NULL mutex is safe.

   Most of the state is simply passed on to the @c ClientSession after
   an accept. It is done here because this is the least bad pathway
   from the top level configuration to the HTTP session.
*/

class L4RSessionAccept : public SessionAccept//, private detail::L4RSessionAcceptOptions
{
private:
  typedef L4RSessionAccept self; ///< Self reference type.
public:
  /** Construction options.
      Provide an easier to remember typedef for clients.
  */
  typedef detail::L4RSessionAcceptOptions Options;

  /** Default constructor.
      @internal We don't use a static default options object because of
      initialization order issues. It is important to pick up data that is read
      from the config file and a static is initialized long before that point.
  */
  //L4RSessionAccept(Options const &opt = Options()) : SessionAccept(nullptr), detail::L4RSessionAcceptOptions(opt) // copy these.
  L4RSessionAccept() : SessionAccept(nullptr)
  {
    SET_HANDLER(&L4RSessionAccept::mainEvent);
    return;
  }

  ~L4RSessionAccept() override { return; }
  bool accept(NetVConnection *, MIOBuffer *, IOBufferReader *) override;
  int mainEvent(int event, void *netvc) override;

  // noncopyable
  L4RSessionAccept(const L4RSessionAccept &) = delete;
  L4RSessionAccept &operator=(const L4RSessionAccept &) = delete;
};