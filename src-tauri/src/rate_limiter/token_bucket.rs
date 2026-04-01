use std::sync::Mutex;
use tokio::time::{sleep, Duration, Instant};

pub struct TokenBucket {
    capacity:    u32,
    tokens:      Mutex<f64>,
    refill_rate: f64,
    last_refill: Mutex<Instant>,
}

impl TokenBucket {
    /// Accetta f64 per comodità nel sito chiamante (es. TokenBucket::new(4.0, 4.0))
    pub fn new(capacity: f64, refill_per_second: f64) -> Self {
        Self {
            capacity:    capacity as u32,
            tokens:      Mutex::new(capacity),
            refill_rate: refill_per_second,
            last_refill: Mutex::new(Instant::now()),
        }
    }

    fn refill(&self) {
        let mut last = self.last_refill.lock().unwrap();
        let elapsed  = last.elapsed().as_secs_f64();
        *last        = Instant::now();
        let mut t    = self.tokens.lock().unwrap();
        *t = (*t + elapsed * self.refill_rate).min(self.capacity as f64);
    }

    /// Non-blocking: true se token disponibile
    pub fn try_acquire(&self) -> bool {
        self.refill();
        let mut t = self.tokens.lock().unwrap();
        if *t >= 1.0 { *t -= 1.0; true } else { false }
    }

    #[allow(dead_code)]
    pub async fn acquire(&self) {
        loop {
            if self.try_acquire() { return; }
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

    pub fn try_consume(&self) -> bool { self.consume() }

    pub fn consume(&self) -> bool {
        let mut ra = self.reset_at.lock().unwrap();
        if Instant::now() >= *ra {
            *self.used.lock().unwrap() = 0;
            *ra = Instant::now() + Duration::from_secs(86400);
        }
        let mut used = self.used.lock().unwrap();
        if *used < self.limit { *used += 1; true } else { false }
    }

    #[allow(dead_code)]
    pub fn remaining(&self) -> u32 {
        self.limit.saturating_sub(*self.used.lock().unwrap())
    }
}
