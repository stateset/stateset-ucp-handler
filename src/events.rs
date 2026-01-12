use crate::models::Order;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum Event {
    OrderCreated { order: Order },
}

#[derive(Clone)]
pub struct EventSender {
    sender: mpsc::Sender<Event>,
}

impl EventSender {
    pub fn new(sender: mpsc::Sender<Event>) -> Self {
        Self { sender }
    }

    pub async fn send(&self, event: Event) {
        let _ = self.sender.send(event).await;
    }
}
