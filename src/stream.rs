//! Independent KCP conversations, with reliable OPEN/DATA/FIN records.
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes};
use kcp::Kcp;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use crate::transport::Network;

pub(crate) const MAX_CONVERSATIONS: usize = 128;

pub(crate) const WRITE_CHUNK: usize = 16 * 1024;

const RECEIVE_BUFFER: usize = 256 * 1024;

const SEND_SEGMENTS: usize = 128;

const SMALL_WRITE_DELAY: Duration = Duration::from_micros(2500);

const SMALL_WRITE_THRESHOLD: usize = 256;

const OPEN: u8 = 0;

const DATA: u8 = 1;

const FIN: u8 = 2;

#[derive(Clone, Default)]
pub(crate) struct Output(pub(crate) Arc<Mutex<VecDeque<Vec<u8>>>>);

impl Write for Output {
    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        let mut queue = self.0.lock();
        // Local congestion drops are recovered by KCP, just like network loss.
        if queue.len() < 512 {
            queue.push_back(packet.to_vec());
        }
        Ok(packet.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct Conversation {
    pub(crate) kcp: Kcp<Output>,
    pub(crate) output: Output,
    pub(crate) opened: bool,
    pub(crate) delivered: bool,
    pub(crate) dropped: Option<Instant>,
    pub(crate) local_fin: bool,
    pub(crate) remote_fin: bool,
    pub(crate) error: Option<io::ErrorKind>,
    pub(crate) io_pending: bool,
    received: VecDeque<Bytes>,
    received_bytes: usize,
    reader: Option<Waker>,
    writer: Option<Waker>,
    open_pending: bool,
    pending_write: Vec<u8>,
    pub(crate) write_deadline: Option<Instant>,
    created: Instant,
}

impl Conversation {
    pub(crate) fn new(id: u32, local: bool) -> io::Result<Self> {
        let output = Output::default();
        // Use KCP message mode internally, so FIN cannot be confused with user bytes.
        // KcpStream concatenates DATA records into a byte stream.
        let mut kcp = Kcp::new(id, output.clone());
        kcp.set_mtu(crate::crypto::MTU - crate::crypto::DATA_HEADER - 16 - 1)?;
        // With congestion control disabled, the send window bounds each burst.
        kcp.set_wndsize(8, 128);
        kcp.set_nodelay(true, 10, 2, true); // allow multiple segments in the first flight
        kcp.set_maximum_resend_times(40);
        Ok(Self {
            kcp,
            output,
            opened: local,
            delivered: local,
            dropped: None,
            local_fin: false,
            remote_fin: false,
            error: None,
            io_pending: false,
            received: VecDeque::new(),
            received_bytes: 0,
            reader: None,
            writer: None,
            open_pending: local,
            pending_write: Vec::new(),
            write_deadline: None,
            created: Instant::now(),
        })
    }

    pub(crate) fn fail(&mut self, kind: io::ErrorKind) {
        self.error = Some(kind);
        self.wake();
    }

    pub(crate) fn wake(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }

    pub(crate) fn receive_records(&mut self) -> io::Result<()> {
        while self.received_bytes < RECEIVE_BUFFER || self.dropped.is_some() {
            let size = match self.kcp.peeksize() {
                Ok(size) => size,
                Err(kcp::Error::RecvQueueEmpty | kcp::Error::ExpectingFragment) => break,
                Err(error) => return Err(error.into()),
            };
            if size == 0 || size > WRITE_CHUNK + 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid KCP record size",
                ));
            }
            let mut record = vec![0; size];
            self.kcp.recv(&mut record)?;
            match record[0] {
                OPEN if !self.opened => {
                    self.opened = true;
                    if size > 1 && self.dropped.is_none() {
                        self.received_bytes += size - 1;
                        self.received.push_back(Bytes::from(record).slice(1..));
                    }
                }
                DATA if self.opened && !self.remote_fin && size > 1 => {
                    if self.dropped.is_none() {
                        self.received_bytes += size - 1;
                        self.received.push_back(Bytes::from(record).slice(1..));
                    }
                }
                FIN if self.opened && !self.remote_fin && size == 1 => self.remote_fin = true,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid KCP record sequence",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn flush_open(&mut self, force: bool) -> io::Result<()> {
        if self.open_pending
            && self.pending_write.is_empty()
            && (force || self.created.elapsed() >= Duration::from_millis(10))
        {
            self.kcp.send(&[OPEN])?;
            self.open_pending = false;
        }
        Ok(())
    }

    // Returns true when the driver needs to schedule a deadline or send now.
    fn queue_write(&mut self, data: &[u8]) -> io::Result<bool> {
        let first = self.pending_write.is_empty();
        if first {
            self.pending_write
                .push(if self.open_pending { OPEN } else { DATA });
            self.write_deadline = Some(Instant::now() + SMALL_WRITE_DELAY);
        }
        self.pending_write.extend_from_slice(data);
        if self.pending_write.len() > SMALL_WRITE_THRESHOLD {
            self.flush_writes()?;
            self.io_pending = true;
            return Ok(true);
        }
        Ok(first)
    }

    pub(crate) fn flush_writes(&mut self) -> io::Result<()> {
        if !self.pending_write.is_empty() {
            self.kcp.send(&self.pending_write)?;
            self.pending_write.clear();
            self.open_pending = false;
            self.write_deadline = None;
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if !self.local_fin {
            self.flush_writes()?;
            self.flush_open(true)?;
            self.kcp.send(&[FIN])?;
            self.local_fin = true;
        }
        Ok(())
    }

    fn check_write(&self) -> io::Result<()> {
        if let Some(kind) = self.error {
            return Err(io::Error::new(kind, "KCP conversation closed"));
        }
        if self.local_fin {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write side closed",
            ));
        }
        Ok(())
    }
}

/// An independent reliable byte stream over one KCP conversation.
/// Implements Tokio AsyncRead/AsyncWrite, including a reliable half-close.
/// Other conversations on the Noise session have their own KCP state and windows.
pub struct KcpStream {
    pub(crate) inner: Arc<Mutex<Conversation>>,
    pub(crate) network: Arc<Network>,
}

impl KcpStream {
    fn notify_io(&self, state: &mut Conversation) {
        state.io_pending = true;
        self.network.io_ready.notify_one();
    }

    /// KCP conversation number, unique within this Noise session.
    pub fn conversation_id(&self) -> u32 {
        self.inner.lock().kcp.conv()
    }
}

impl fmt::Debug for KcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KcpStream")
            .field("conversation_id", &self.conversation_id())
            .finish_non_exhaustive()
    }
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        let mut state = self.inner.lock();
        let _ = state.finish();
        state.dropped = Some(Instant::now());
        state.received.clear();
        state.received_bytes = 0;
        self.notify_io(&mut state);
        // Network's destructor keeps the UDP task running for a bounded drain.
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = self.inner.lock();
        if let Some(mut bytes) = state.received.pop_front() {
            let count = bytes.len().min(buf.remaining());
            buf.put_slice(&bytes[..count]);
            bytes.advance(count);
            let was_full = state.received_bytes >= RECEIVE_BUFFER;
            state.received_bytes -= count;
            if was_full && state.received_bytes < RECEIVE_BUFFER {
                self.notify_io(&mut state);
            }
            if !bytes.is_empty() {
                state.received.push_front(bytes);
            }
            return Poll::Ready(Ok(()));
        }
        if state.remote_fin {
            return Poll::Ready(Ok(()));
        }
        if let Some(kind) = state.error {
            return Poll::Ready(Err(io::Error::new(kind, "KCP conversation closed")));
        }
        state.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.inner.lock();
        if let Err(error) = state.check_write() {
            return Poll::Ready(Err(error));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if state.kcp.wait_snd() >= SEND_SEGMENTS {
            state.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let staged = state.pending_write.len().saturating_sub(1);
        let count = buf.len().min(WRITE_CHUNK - staged);
        match state.queue_write(&buf[..count]) {
            Ok(notify) => {
                if notify {
                    self.network.io_ready.notify_one();
                }
                Poll::Ready(Ok(count))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        // Hyper can supply headers and a small body in separate slices. Put
        // them in the same first KCP record instead of waiting for a header ACK.
        let mut data = Vec::new();
        for buffer in buffers {
            let count = buffer.len().min(WRITE_CHUNK - data.len());
            data.extend_from_slice(&buffer[..count]);
            if data.len() == WRITE_CHUNK {
                break;
            }
        }
        self.poll_write(cx, &data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.inner.lock();
        if let Some(kind) = state.error {
            return Poll::Ready(Err(io::Error::new(kind, "KCP conversation closed")));
        }
        if state.write_deadline.is_some() {
            state.flush_writes()?;
            self.notify_io(&mut state);
        }
        if state.kcp.wait_snd() == 0 {
            return Poll::Ready(Ok(()));
        }
        state.writer = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.inner.lock();
        if let Some(kind) = state.error {
            return Poll::Ready(Err(io::Error::new(kind, "KCP conversation closed")));
        }
        let result = state.finish();
        if result.is_ok() {
            self.notify_io(&mut state);
        }
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn character_writes_share_one_record_and_one_deadline() {
        let mut conversation = Conversation::new(1, true).unwrap();
        let start = Instant::now();
        assert!(conversation.queue_write(b"h").unwrap());
        tokio::time::advance(Duration::from_millis(2)).await;
        for byte in b"ello" {
            assert!(!conversation.queue_write(&[*byte]).unwrap());
        }
        assert_eq!(conversation.write_deadline, Some(start + SMALL_WRITE_DELAY));
        assert_eq!(conversation.kcp.wait_snd(), 0);

        conversation.flush_writes().unwrap();
        conversation.kcp.update(0).unwrap();
        let mut packets = conversation.output.0.lock();
        assert_eq!(packets.len(), 1);
        let mut peer = Conversation::new(1, false).unwrap();
        peer.kcp.input(&packets.pop_front().unwrap()).unwrap();
        peer.receive_records().unwrap();
        assert_eq!(peer.received.pop_front().unwrap(), &b"hello"[..]);
    }

    #[test]
    fn first_flight_sends_two_segments_without_an_ack() {
        let mut conversation = Conversation::new(1, true).unwrap();
        let mut record = vec![0; conversation.kcp.mss() + 1];
        record[0] = OPEN;
        conversation.kcp.send(&record).unwrap();
        conversation.kcp.update(0).unwrap();
        conversation.kcp.flush().unwrap();

        assert_eq!(conversation.output.0.lock().len(), 2);
    }
}
