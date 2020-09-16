use std::sync::Arc;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct ServerContext {
    shared: Arc<Shared>,
}

impl Default for ServerContext {
    fn default() -> Self {
        Self {
            shared: Arc::new(Shared {}),
        }
    }
}

#[derive(Debug)]
pub struct Shared {}
