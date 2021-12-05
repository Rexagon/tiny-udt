#[derive(Debug, thiserror::Error)]
pub enum ConnectionSetupError {
    #[error("Connection setup error: connection time out")]
    ConnectionTimeOut,
    #[error("Connection setup error: connection rejected")]
    ConnectionRejected,
    #[error("Connection setup error: unable to create/configure UDP socket")]
    UnableRoCreateSocket,
    #[error("Connection setup error: abort for security reasons")]
    SecurityAbort,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("Connection failure")]
    Failure,
    #[error("Connection was broken")]
    Broken,
    #[error("Connection does not exist")]
    NotExist,
}
