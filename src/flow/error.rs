use thiserror::Error;
use serde::ser::StdError;
#[derive(Debug, Error)]
pub enum FlowError {
    #[error("IO Error")]
    Io(#[from] std::io::Error),
    #[error("End of stream")]
    Eof,
    #[error("Unexpected data received")]
    UnexpectedData,
    #[error("Cannot find a matching outbound")]
    NoOutbound,
      

}

pub type FlowResult<T> = Result<T, FlowError>;
// 确保可以将 FlowError 转换为 Box<dyn Error + Send>
impl From<FlowError> for Box<dyn std::error::Error + Send> {
    fn from(error: FlowError) -> Self {
        Box::new(error)
    }
}