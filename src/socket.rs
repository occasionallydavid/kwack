use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use parking_lot::Mutex;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::PublicKey;

pub(crate) const QUEUE: usize = 256;
pub(crate) const VIRTUAL_LOCAL: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
    4433,
);
pub(crate) const VIRTUAL_REMOTE: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
    4433,
);

#[derive(Debug, Clone, Copy)]
pub(crate) enum Target {
    Peer(PublicKey),
    Raw,
}
#[derive(Debug)]
pub(crate) struct Outbound {
    pub target: Target,
    pub destination: SocketAddr,
    pub data: Bytes,
}
#[derive(Debug)]
pub(crate) struct Inbound {
    pub source: SocketAddr,
    pub data: Bytes,
}

/// A bounded datagram queue used by Quinn. Only the dispatcher owns the physical socket.
#[derive(Debug)]
pub(crate) struct VirtualSocket {
    pub incoming: Mutex<mpsc::Receiver<Inbound>>,
    pub outgoing: mpsc::Sender<Outbound>,
    pub target: Target,
    pub local: SocketAddr,
}

impl AsyncUdpSocket for VirtualSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller(Mutex::new(PollSender::new(self.outgoing.clone()))))
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP segmentation is disabled",
            ));
        }
        self.outgoing
            .try_send(Outbound {
                target: self.target,
                destination: transmit.destination,
                data: Bytes::copy_from_slice(transmit.contents),
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => io::Error::from(io::ErrorKind::WouldBlock),
                mpsc::error::TrySendError::Closed(_) => io::Error::from(io::ErrorKind::BrokenPipe),
            })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        match self.incoming.lock().poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Some(packet)) => {
                if packet.data.len() > bufs[0].len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "receive buffer too small",
                    )));
                }
                bufs[0][..packet.data.len()].copy_from_slice(&packet.data);
                meta[0] = RecvMeta {
                    addr: packet.source,
                    len: packet.data.len(),
                    stride: packet.data.len(),
                    ecn: None,
                    dst_ip: Some(self.local.ip()),
                };
                Poll::Ready(Ok(1))
            }
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

#[derive(Debug)]
struct Poller(Mutex<PollSender<Outbound>>);
impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.0.lock();
        match sender.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Ok(())) => {
                sender.abort_send();
                Poll::Ready(Ok(()))
            }
        }
    }
}
