/** @file

  L4RClientTransaction.cc - The Transaction class for L4R*

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

#include "L4RClientTransaction.h"
#include "Http1ClientSession.h"
#include "L4RSM.h"

void
L4RClientTransaction::release(IOBufferReader *r)
{
  // Must set this inactivity count here rather than in the session because the state machine
  // is not availble then
  MgmtInt ka_in = current_reader->t_state.txn_conf->keep_alive_no_activity_timeout_in;
  set_inactivity_timeout(HRTIME_SECONDS(ka_in));

  parent->clear_session_active();
  parent->ssn_last_txn_time = Thread::get_hrtime();

  // Make sure that the state machine is returning
  //  correct buffer reader
  ink_assert(r == sm_reader);
  if (r != sm_reader) {
    this->do_io_close();
  } else {
    super_type::release(r);
  }
}

void
L4RClientTransaction::set_parent(BasicProxyClientSession *new_parent)
{
  parent                           = new_parent;
  L4RClientSession *l4r_parent = dynamic_cast<L4RClientSession *>(new_parent);
  if (l4r_parent) {
    outbound_port        = l4r_parent->outbound_port;
    outbound_ip4         = l4r_parent->outbound_ip4;
    outbound_ip6         = l4r_parent->outbound_ip6;
    outbound_transparent = l4r_parent->f_outbound_transparent;
  }
  super_type::set_parent(new_parent);
}

void
L4RClientTransaction::transaction_done()
{
  if (parent) {
    static_cast<L4RClientSession *>(parent)->release_transaction();
  }
}

bool
L4RClientTransaction::allow_half_open() const
{
  return current_reader ? current_reader->t_state.txn_conf->allow_half_open > 0 : true;
}
