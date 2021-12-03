use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct AckWindow<const SIZE: usize> {
    items: Vec<AckWindowItem>,
    /// Index of the latest ACK record
    head: usize,
    /// Index of the oldest ACK record
    tail: usize,
}

impl<const SIZE: usize> AckWindow<SIZE> {
    pub fn new() -> Self {
        let mut window = Self {
            items: vec![Default::default(); SIZE],
            head: 0,
            tail: 0,
        };
        window.items[0].seq_no = -1;

        window
    }

    /// Write an ACK record into the window
    pub fn store(&mut self, seq_no: i32, data_seq_no: i32) {
        unsafe {
            *self.items.get_unchecked_mut(self.head) = AckWindowItem {
                timestamp: Instant::now(),
                seq_no,
                data_seq_no,
            }
        };

        self.head = (self.head + 1) % SIZE;
        if self.head == self.tail {
            self.tail = (self.tail + 1) % SIZE;
        }
    }

    /// Search the ACK-2 "seq" in the window, find out the DATA "ack" and calculate RTT
    pub fn acknowledge(&mut self, seq_no: i32) -> Option<Acknowledgement> {
        // Head has not exceeded the physical boundary of the window
        if self.head >= self.tail {
            for i in self.tail..self.head {
                let item = unsafe { self.items.get_unchecked_mut(i) };
                if seq_no != item.seq_no {
                    continue;
                }

                let ack = item.make_ack();
                self.bump_or_reset(i);
                return Some(ack);
            }

            return None;
        }

        // Head has exceeded the physical window boundary, so it is behind tail
        for i in self.tail..(self.head + SIZE) {
            let item = unsafe { self.items.get_unchecked_mut(i % SIZE) };
            if seq_no != item.seq_no {
                continue;
            }

            let ack = item.make_ack();
            self.bump_or_reset(i);
            return Some(ack);
        }

        None
    }

    #[inline(always)]
    fn bump_or_reset(&mut self, i: usize) {
        if i + 1 == self.head {
            self.head = 0;
            self.tail = 0;
            self.items[0].seq_no = -1;
        } else {
            self.tail = (i + 1) % SIZE;
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Acknowledgement {
    /// The DATA ACK no. that matches the ACK-2 no.
    pub data_seq_no: i32,
    /// Round-trip delay (saturated)
    pub rtt: Duration,
}

#[derive(Debug, Clone)]
struct AckWindowItem {
    /// The timestamp when the ACK was sent
    timestamp: Instant,
    /// Seq. No. for the ACK packet
    seq_no: i32,
    /// Data Seq. No. carried by the ACK packet
    data_seq_no: i32,
}

impl AckWindowItem {
    #[inline(always)]
    fn make_ack(&self) -> Acknowledgement {
        Acknowledgement {
            data_seq_no: self.data_seq_no,
            rtt: Instant::now().saturating_duration_since(self.timestamp),
        }
    }
}

impl Default for AckWindowItem {
    fn default() -> Self {
        Self {
            timestamp: Instant::now(),
            seq_no: 0,
            data_seq_no: 0,
        }
    }
}

#[derive(Debug)]
pub struct PacketTimeWindow<const ARRIVAL_SIZE: usize, const PROBE_SIZE: usize> {
    /// Packet information window
    packet_window: Vec<Duration>,
    /// Position pointer of the packet info window
    packet_window_index: usize,

    /// Record inter-packet time for probing packet pairs
    probe_window: Vec<Duration>,
    /// Position pointer to the probing window
    probe_window_index: usize,

    /// Last packet sending time
    last_sent_time: Instant,
    /// Minimum packet sending interval
    min_packet_sending_interval: Duration,

    /// Last packet arrival time
    last_arrival_time: Instant,
    /// Current packet arrival time
    current_arrival_time: Instant,
    /// Arrival time of the first probing packet
    probe_time: Instant,
}

impl<const ARRIVAL_SIZE: usize, const PROBE_SIZE: usize>
    PacketTimeWindow<ARRIVAL_SIZE, PROBE_SIZE>
{
    pub fn new() -> Self {
        let last_arrival_time = Instant::now();

        Self {
            packet_window: vec![Duration::from_secs(1); ARRIVAL_SIZE],
            packet_window_index: 0,
            probe_window: vec![Duration::from_millis(1); PROBE_SIZE],
            probe_window_index: 0,
            last_sent_time: last_arrival_time,
            min_packet_sending_interval: Default::default(),
            last_arrival_time,
            current_arrival_time: last_arrival_time,
            probe_time: last_arrival_time,
        }
    }

    #[allow(unused)]
    pub fn min_packet_sending_interval(&self) -> Duration {
        self.min_packet_sending_interval
    }

    pub fn get_packet_receive_speed(&self) -> u64 {
        // SAFETY: `packet_window` is initialized right after that
        let mut packet_window =
            unsafe { std::mem::MaybeUninit::<[Duration; ARRIVAL_SIZE]>::uninit().assume_init() };
        packet_window.copy_from_slice(&self.packet_window);

        let median = *packet_window.select_nth_unstable(ARRIVAL_SIZE / 2).1;
        let median = median.as_micros() as u64;

        let mut count = 0;
        let mut total_duration = 0;
        let upper = median << 3;
        let lower = median >> 3;

        for duration in packet_window {
            let duration = duration.as_micros() as u64;
            if (lower..upper).contains(&duration) {
                count += 1;
                total_duration += duration;
            }
        }

        if count > (ARRIVAL_SIZE >> 1) {
            let average_duration = total_duration as f64 / count as f64;
            (1000000.0f64 / average_duration) as u64
        } else {
            0
        }
    }

    pub fn get_bandwidth(&self) -> u64 {
        // SAFETY: `probe_window` is initialized right after that
        let mut probe_window =
            unsafe { std::mem::MaybeUninit::<[Duration; PROBE_SIZE]>::uninit().assume_init() };
        probe_window.copy_from_slice(&self.probe_window);

        let median = *probe_window.select_nth_unstable(PROBE_SIZE / 2).1;
        let median = median.as_micros() as u64;

        let mut count = 1;
        let mut total_duration = median;
        let upper = median << 3;
        let lower = median >> 3;

        for duration in probe_window {
            let duration = duration.as_micros() as u64;
            if (lower..upper).contains(&duration) {
                count += 1;
                total_duration += duration;
            }
        }

        let average_duration = total_duration as f64 / count as f64;
        (1000000.0f64 / average_duration) as u64
    }

    #[allow(unused)]
    pub fn on_packet_sent(&mut self, current_time: Instant) {
        let interval = current_time.saturating_duration_since(self.last_sent_time);
        if (interval < self.min_packet_sending_interval) && !interval.is_zero() {
            self.min_packet_sending_interval = interval;
        }

        self.last_sent_time = current_time;
    }

    pub fn on_packet_arrival(&mut self) {
        self.current_arrival_time = Instant::now();
        // SAFETY: `packet_window` size is always ARRIVAL_SIZE and `packet_window_index`
        // is always incremented with modulo ARRIVAL_SIZE
        unsafe {
            *self
                .packet_window
                .get_unchecked_mut(self.packet_window_index) = self
                .current_arrival_time
                .saturating_duration_since(self.last_arrival_time);
        }
        self.packet_window_index = (self.packet_window_index + 1) % ARRIVAL_SIZE;
        self.last_arrival_time = self.current_arrival_time;
    }

    pub fn probe1_arrival(&mut self) {
        self.probe_time = Instant::now();
    }

    pub fn probe2_arrival(&mut self) {
        self.current_arrival_time = Instant::now();
        // SAFETY: `probe_window` size is always PROBE_SIZE and `probe_window_index`
        // is always incremented with modulo PROBE_SIZE
        unsafe {
            *self.probe_window.get_unchecked_mut(self.probe_window_index) = self
                .current_arrival_time
                .saturating_duration_since(self.probe_time);
        }
        self.probe_window_index = (self.probe_window_index + 1) % PROBE_SIZE;
    }
}
