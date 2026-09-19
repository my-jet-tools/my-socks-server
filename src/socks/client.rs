use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::{
    Command, Greeting, METHOD_USER_PASS, MethodSelection, ProtocolError, Reply, ReplyCode, Request,
    TargetAddr, UserPassRequest, UserPassResponse,
};

/// Failure of [`client_handshake`].
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("proxy does not accept username/password authentication (answered {0:#04x})")]
    MethodRejected(u8),
    #[error("proxy rejected the credentials")]
    AuthRejected,
    #[error("proxy refused the request: {0}")]
    RequestRejected(ReplyCode),
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Protocol(ProtocolError::Io(error))
    }
}

/// Client side of the protocol: greeting, username/password authentication and `CONNECT`
/// over an already established connection to the proxy. Used by tests and the stress example.
///
/// # Errors
/// I/O failure, a malformed answer, or the proxy refusing a step.
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    username: &str,
    password: &str,
    target: &TargetAddr,
) -> Result<Reply, ClientError> {
    let greeting = Greeting {
        methods: vec![METHOD_USER_PASS],
    };
    stream.write_all(&greeting.encode()?).await?;
    let selection = MethodSelection::read_from(stream).await?;
    if selection.method != METHOD_USER_PASS {
        return Err(ClientError::MethodRejected(selection.method));
    }

    let credentials = UserPassRequest {
        username: username.as_bytes().to_vec(),
        password: password.as_bytes().to_vec(),
    };
    stream.write_all(&credentials.encode()?).await?;
    if !UserPassResponse::read_from(stream).await?.is_success() {
        return Err(ClientError::AuthRejected);
    }

    let request = Request {
        command: Command::Connect,
        target: target.clone(),
    };
    stream.write_all(&request.encode()?).await?;
    let reply = Reply::read_from(stream).await?;
    if reply.code != ReplyCode::Succeeded {
        return Err(ClientError::RequestRejected(reply.code));
    }
    Ok(reply)
}
