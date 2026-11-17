use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

use crate::{Client, Error};

/// Managed loopback byte-stream bridge for unmodified reqwest or ureq clients.
/// Each accepted TCP connection opens a stream to the already pinned peer.
/// Keep this object alive for as long as the HTTP client is in use.
pub struct ReqwestBridge {
    address: SocketAddr,
    task: JoinHandle<()>,
}
impl ReqwestBridge {
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }
}
impl Drop for ReqwestBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Client {
    pub async fn reqwest_bridge(&self) -> Result<ReqwestBridge, Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let connection = self.connection().clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>match accepted {
                        Ok((mut tcp,_))=>{
                            let connection=connection.clone();
                            // Bound the local bridge's concurrency and handshake wait.
                            if tasks.len()>=64 {continue;}
                            tasks.spawn(async move {
                                if let Ok(Ok(mut stream))=tokio::time::timeout(Duration::from_secs(10),connection.open_bi()).await {
                                    let _=tokio::time::timeout(Duration::from_secs(300),copy_bidirectional(&mut tcp,&mut stream)).await;
                                    let _=stream.shutdown().await;
                                }
                            });
                        }
                        Err(_)=>break,
                    },
                    _=connection.closed()=>break,
                    Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                }
            }
        });
        Ok(ReqwestBridge { address, task })
    }
}
