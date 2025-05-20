use std::sync::Mutex;
use uuid::Uuid;

pub struct AppState {
    pub nonce: Mutex<Uuid>,
}