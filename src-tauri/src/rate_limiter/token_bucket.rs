
use std::sync::Mutex;
use std::time::Instant;
use tokio::time::{sleep, Duration};

/// Thread-safe token bucket for rate limiting.
pub struct TokenBucket {
    tokens:       Mutex<f64>,
    capacity:     f64,
    refill_rate:  f64,   // tokens per second
    last_refill:  Mutex<Instant>,
}

impl TokenBucket {
    /// `capacity`: max burst, `requests_per_minute`: steady-state rate.
    pub fn new(capacity: f64, requests_per_minute: f64) -> Self {
        Self {
            tokens:      Mutex::new(capacity),
            capacity,
            refill_rate: requests_per_minute / 60.0,
            last_refill: Mutex::new(Instant::now()),
        }
    }

    fn refill(&self) {
        let now = Instant::now();
        let mut last = self.last_refill.lock().unwrap();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *last = now;
        let mut tokens = self.tokens.lock().unwrap();
        *tokens = (*tokens + elapsed * self.refill_rate).min(self.capacity);
    }

    pub fn try_acquire(&self) -> bool {
        self.refill();
        let mut tokens = self.tokens.lock().unwrap();
        if *tokens >= 1.0 { *tokens -= 1.0; true } else { false }
    }

    /// Async: wait until a token is available.
    pub async fn acquire(&self) {
        loop {
            if self.try_acquire() { return; }
            sleep(Duration::from_millis(500)).await;
        }
    }
}

/// Per-API daily counter (persisted across restarts via SQLite).
pub struct DailyQuota {
    used:      Mutex<u32>,
    max_daily: u32,
    date:      Mutex<chrono::NaiveDate>,
}

impl DailyQuota {
    pub fn new(max_daily: u32) -> Self {
        Self { used: Mutex::new(0), max_daily, date: Mutex::new(chrono::Utc::now().date_naive()) }
    }

    fn reset_if_new_day(&self) {
        let today = chrono::Utc::now().date_naive();
        let mut d = self.date.lock().unwrap();
        if *d != today { *d = today; *self.used.lock().unwrap() = 0; }
    }

    pub fn try_consume(&self) -> bool {
        self.reset_if_new_day();
        let mut used = self.used.lock().unwrap();
        if *used < self.max_daily { *used += 1; true } else { false }
    }

    pub fn remaining(&self) -> u32 {
        self.reset_if_new_day();
        self.max_daily.saturating_sub(*self.used.lock().unwrap())
    }
}
