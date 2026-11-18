use std::future::Future;
use std::io;
use std::time::Duration;

use http::Request;
use hyper::body::{Body, Incoming};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::task::JoinSet;
use tower_service::Service;

use crate::{Connection, Error, Server};

impl Server {
    /// Serves a cloneable Tower HTTP service over authenticated KCP conversations.
    /// Each request carries its authenticated [`crate::PeerIdentity`] in its extensions.
    pub async fn serve<S, B>(self, service: S) -> Result<(), Error>
    where
        S: Service<Request<Incoming>, Response = http::Response<B>> + Clone + Send + 'static,
        S::Future: Send,
        S::Error: Into<Error>,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Error>,
    {
        self.serve_with_shutdown(service, std::future::pending::<()>())
            .await
    }

    /// Cancels active handlers and closes the transport when shutdown resolves.
    pub async fn serve_with_shutdown<S, B>(
        mut self,
        service: S,
        shutdown: impl Future<Output = ()> + Send,
    ) -> Result<(), Error>
    where
        S: Service<Request<Incoming>, Response = http::Response<B>> + Clone + Send + 'static,
        S::Future: Send,
        S::Error: Into<Error>,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Error>,
    {
        tokio::pin!(shutdown);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _=&mut shutdown=>{self.handle().shutdown().await?;break;}
                result=self.accept(), if tasks.len() < 256 =>match result {
                    Ok(connection)=>{let service=service.clone();tasks.spawn(async move {serve_connection(connection,service).await;});}
                    Err(error)=>{if error.downcast_ref::<io::Error>().is_some_and(|e| e.kind()==io::ErrorKind::BrokenPipe) {break;}return Err(error);}
                },
                Some(result)=tasks.join_next(),if !tasks.is_empty()=>{
                    if let Err(error)=result {tracing::error!(%error,"HTTP connection task failed");}
                },
            }
        }
        // JoinSet drop cancels outstanding connection and request tasks.
        Ok(())
    }
}

async fn serve_connection<S, B>(connection: Connection, service: S)
where
    S: Service<Request<Incoming>, Response = http::Response<B>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Error>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error>,
{
    let identity = connection.peer_identity();
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            stream=connection.accept_stream(), if tasks.len() < 64 =>match stream {
                Ok(stream)=>{
                    let service=TowerToHyperService::new(service.clone());
                    let service=hyper::service::service_fn(move |mut request: Request<Incoming>| {
                        request.extensions_mut().insert(identity);
                        hyper::service::Service::call(&service, request)
                    });
                    tasks.spawn(async move {
                        if let Err(error)=hyper::server::conn::http1::Builder::new()
                            .timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(15))
                            .max_buf_size(64*1024).serve_connection(TokioIo::new(stream),service).await {
                            tracing::debug!(%error,"HTTP stream closed");
                        }
                    });
                }
                Err(_)=>break,
            },
            Some(result)=tasks.join_next(),if !tasks.is_empty()=>{
                if let Err(error)=result {tracing::error!(%error,peer=%identity.public_key(),"HTTP stream task failed");}
            },
        }
    }
}
