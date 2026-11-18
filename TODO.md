# Transport review TODO

- [ ] **Validate KCP segments before handing them to KCP.** Check the framing and fragment counts of every segment in a datagram before calling `Kcp::input`. Invalid input should leave the conversation state intact and the shared UDP driver running. Verify that another session can still exchange data after a malformed segment is rejected. See [segment handling](src/transport.rs#L209).

- [ ] **Limit sessions per authorized identity.** Give unconfirmed handshakes and confirmed sessions separate per-identity budgets, and expire pending handshakes sooner. Retain a global cap for aggregate load. Verify that one identity at its limit leaves room for another identity to connect and reach the HTTP service. See [session admission](src/transport.rs#L726) and the [HTTP connection limit](src/server.rs#L49).

- [ ] **Reclaim incomplete conversation opens.** Validate the first segment before allocating a conversation slot, and set a deadline for receiving a complete `OPEN`. Verify that incomplete opens expire even if keepalives continue, and that a subsequent valid stream can use the freed capacity. See [conversation allocation](src/transport.rs#L209) and [cleanup](src/transport.rs#L285).

- [ ] **Keep delayed packets from undoing endpoint roaming.** Track the newest authenticated packet eligible to update the remote address separately from the replay window. Compare key generations before packet counters. Verify that reordering on the old path leaves replies directed to the new endpoint, including across a rekey. See [endpoint updates](src/transport.rs#L793).
