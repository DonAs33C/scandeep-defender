use std::sync::Mutex;
use tokio::time::{sleep, Duration, Instant};

pub struct TokenBucket {
    capacity:     u32,
    tokens:       Mutex<f64>,
    refill_rate:  f64,           // token/secondo
    last_refill:  Mutex<Instant>,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_per_second: f64) -> Self {
        Self {
            capacity,
            tokens:      Mutex::new(capacity as f64),
            refill_rate: refill_per_second,
            last_refill: Mutex::new(Instant::now()),
        }
    }

    fn refill(&self) {
        let mut last = self.last_refill.lock().unwrap();
        let elapsed = last.elapsed().as_secs_f64();
        *last = Instant::now();
        let mut tokens = self.tokens.lock().unwrap();
        *tokens = (*tokens + elapsed * self.refill_rate).min(self.capacity as f64);
    }

    #[allow(dead_code)]   // sarà usato dal rate-limiter prima di ogni chiamata API
    pub async fn acquire(&self) {
        loop {
            self.refill();
            let mut tokens = self.tokens.lock().unwrap();
            if *tokens >= 1.0 {
                *tokens -= 1.0;
                return;
            }
            drop(tokens);
            sleep(Duration::from_millis(100)).await;
        }
    }
}

pub struct DailyQuota {
    limit:    u32,
    used:     Mutex<u32>,
    reset_at: Mutex<Instant>,
}

impl DailyQuota {
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            used:     Mutex::new(0),
            reset_at: Mutex::new(Instant::now() + Duration::from_secs(86400)),
        }
    }

    pub fn consume(&self) -> bool {
        let mut reset_at = self.reset_at.lock().unwrap();
        if Instant::now() >= *reset_at {
            *self.used.lock().unwrap() = 0;
            *reset_at = Instant::now() + Duration::from_secs(86400);
        }
        let mut used = self.used.lock().unwrap();
        if *used < self.limit {
            *used += 1;
            true
        } else {
            false
        }
    }

    #[allow(dead_code)]   // esposto per la UI "quota rimanente oggi"
    pub fn remaining(&self) -> u32 {
        let used = *self.used.lock().unwrap();
        self.limit.saturating_sub(used)
    }
}
