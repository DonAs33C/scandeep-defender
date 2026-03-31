
use tokio::sync::mpsc;
use crate::engine::job::ScanJob;

pub struct JobQueue {
    sender: mpsc::UnboundedSender<ScanJob>,
}

impl JobQueue {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<ScanJob>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { sender: tx }, rx)
    }

    pub fn enqueue(&self, job: ScanJob) -> Result<(), String> {
        self.sender.send(job).map_err(|e| e.to_string())
    }

    pub fn len_hint(&self) -> usize {
        // approximate — mpsc channels don't expose size
        0
    }
}
