use tokio::sync::mpsc;
use crate::engine::job::ScanJob;

pub struct JobQueue {
    #[allow(dead_code)]
    sender: mpsc::UnboundedSender<ScanJob>,
    receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<ScanJob>>,
}

impl JobQueue {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            sender:   tx,
            receiver: tokio::sync::Mutex::new(rx),
        }
    }

    #[allow(dead_code)]
    pub fn enqueue(&self, job: ScanJob) -> Result<(), String> {
        self.sender.send(job).map_err(|e| e.to_string())
    }

    #[allow(dead_code)]
    pub fn len_hint(&self) -> usize {
        // mpsc non espone la lunghezza — stima non disponibile
        0
    }

    pub async fn next(&self) -> Option<ScanJob> {
        self.receiver.lock().await.recv().await
    }
}
