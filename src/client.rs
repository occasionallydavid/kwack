use std::io;

use http::Request;
use hyper::body::{Body, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;

use crate::{Client, Error};

impl Client {
    /// Sends an HTTP request on a new QUIC stream to the pinned peer.
    ///
    /// The URI must be an origin-relative path. Set HTTP routing metadata such
    /// as `Host` on the request itself. The response body streams directly from
    /// Hyper; callers control timeouts and body collection.
    pub async fn send<B>(&self, mut request: Request<B>) -> Result<http::Response<Incoming>, Error>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Error>,
    {
        if request.uri().scheme().is_some()
            || request.uri().authority().is_some()
            || !request.uri().path().starts_with('/')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "use an origin-relative path; the transport pins one remote peer",
            )
            .into());
        }
        // Each QUIC stream carries one HTTP request and its response.
        request.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
        let stream = self.connection().open_bi().await?;
        let (mut sender, driver) = http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            if let Err(error) = driver.await {
                tracing::debug!(%error, "HTTP client stream closed");
            }
        });
        sender.send_request(request).await.map_err(Into::into)
    }
}
