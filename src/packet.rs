use std::io::Read;

#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    /// Packet sequence number
    pub seq_no: u32,
    /// Message number
    pub msg_no: u32,
    /// Packet timestamp
    pub timestamp: u32,
    /// Socket ID
    pub id: u32,
}

#[derive(Debug, Clone, Copy)]
enum PacketData {
    /// 0000 - Handshake
    Handshake(HandshakeControlInfo),
    /// 0001 - Keep-alive
    KeepAlive,
    /// 0010 - Acknowledgement (ACK)
    Ack(AckControlInfo),
    /// 0011 - Loss Report (NAK)
    Nak(NakControlInfo),
    /// 0100 - Congestion Warning (unused)
    CongestionWarning,
    /// 0101 - Shutdown
    Shutdown,
    /// 0110 - Acknowledgement of Acknowledgement (ACK-2)
    Ack2,
    /// 0111 - Message Drop Request
    MessageDropRequest(MessageDropRequestControlInfo),
}

/// Message Drop Request packet control info
#[derive(Debug, Copy, Clone)]
pub struct MessageDropRequestControlInfo {
    /// First sequence number in the message
    first_seq_no: u32,
    /// Last sequence number in the message
    last_seq_no: u32,
}

/// Acknowledgement of Acknowledgement (ACK2) packet control info
#[derive(Debug, Copy, Clone)]
pub struct Ack2ControlInfo {
    /// ACK packet seq. no.
    pub seq_no: i32,
}

/// Negative-acknowledgment packet control info
#[derive(Debug, Copy, Clone)]
pub enum NakControlInfo {
    Single {
        /// Lost packet seqno
        seq_no: u32,
    },
    Multiple {
        /// Compressed loss information
        loss_data: [u32; 2],
    },
}

/// Acknowledgement packet control info
#[derive(Debug, Copy, Clone)]
pub struct AckControlInfo {
    /// The packet sequence number to which all the
    /// previous packets have been received (excluding)
    pub received_last_ack: i32,
    /// Optional additional info
    pub info: Option<AckAdditionalInfo>,
}

#[derive(Debug, Copy, Clone)]
pub struct AckAdditionalInfo {
    /// RTT (in microseconds)
    pub rtt: u32,
    /// RTT variance
    pub rtt_var: u32,
    /// Available buffer size (in bytes)
    pub buffer_size: u32,
    /// An optional tuple of:
    /// - packets receiving rate (in number of packets per second)
    /// - estimated link capacity (in number of packets per second)
    pub speed_and_bandwidth: Option<(u32, u32)>,
}

/// Handshake packet control info
#[derive(Debug, Copy, Clone)]
pub struct HandshakeControlInfo {
    /// UDT socket type
    pub socket_type: SocketType,
    /// Random initial sequence number
    pub isn: u32,
    /// Maximum segment size
    pub mss: u32,
    /// Flow control window size
    pub flight_flag_size: u32,
    /// Connection request type
    pub request_type: i32,
    /// Socket ID
    pub id: u32,
    /// SYN cookie
    pub cookie: u32,
    /// The IP address that the peer's UDP port is bound to
    pub ip: [u32; 4],
}

impl HandshakeControlInfo {
    pub fn serialize(&self, buffer: &mut [u8]) -> bool {
        if buffer.len() < HANDSHAKE_SIZE {
            return false;
        }

        // 1) 32 bits: UDT version
        buffer[0..8].copy_from_slice(&[UDT_VERSION, 0, 0, 0]);

        // 2) 32 bits: Socket Type (STREAM or DGRAM)
        buffer[4..8].copy_from_slice(&[
            match self.socket_type {
                SocketType::Stream => 1,
                SocketType::Datagram => 2,
            },
            0,
            0,
            0,
        ]);

        // 3) 32 bits: initial packet sequence number
        buffer[8..12].copy_from_slice(&self.isn.to_le_bytes());

        // 4) 32 bits: maximum packet size (including UDP/IP headers)
        buffer[12..16].copy_from_slice(&self.mss.to_le_bytes());

        // 5) 32 bits: maximum flow window size
        buffer[16..20].copy_from_slice(&self.flight_flag_size.to_le_bytes());

        // 6) 32 bits: connection type
        buffer[20..24].copy_from_slice(&self.request_type.to_le_bytes());

        // 7) 32 bits: socket ID
        buffer[24..28].copy_from_slice(&self.id.to_le_bytes());

        // 8) 32 bits: SYN cookie
        buffer[28..32].copy_from_slice(&self.cookie.to_le_bytes());

        // 9) 128 bits: the IP address of the peer's UDP socket
        buffer[32..36].copy_from_slice(&self.ip[0].to_le_bytes());
        buffer[36..40].copy_from_slice(&self.ip[1].to_le_bytes());
        buffer[40..44].copy_from_slice(&self.ip[2].to_le_bytes());
        buffer[44..48].copy_from_slice(&self.ip[3].to_le_bytes());

        // Done
        true
    }

    pub fn deserialize(buffer: &[u8]) -> Option<Self> {
        if buffer.len() < HANDSHAKE_SIZE {
            return None;
        }

        // 1) 32 bits: UDT version
        if buffer[0] != UDT_VERSION {
            return None;
        }

        // 2) 32 bits: Socket Type (STREAM or DGRAM)
        let socket_type = match buffer[4] {
            1 => SocketType::Stream,
            2 => SocketType::Datagram,
            _ => return None,
        };

        // 3) 32 bits: initial packet sequence number
        let isn = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);

        // 4) 32 bits: maximum packet size (including UDP/IP headers)
        let mss = u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]);

        // 5) 32 bits: maximum flow window size
        let flight_flag_size = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);

        // 6) 32 bits: connection type
        let request_type = i32::from_le_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]);

        // 7) 32 bits: socket ID
        let id = u32::from_le_bytes([buffer[24], buffer[25], buffer[26], buffer[27]]);

        // 8) 32 bits: SYN cookie
        let cookie = u32::from_le_bytes([buffer[28], buffer[29], buffer[30], buffer[31]]);

        // 9) 128 bits: the IP address of the peer's UDP socket
        let ip = [
            u32::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35]]),
            u32::from_le_bytes([buffer[36], buffer[37], buffer[38], buffer[39]]),
            u32::from_le_bytes([buffer[40], buffer[41], buffer[42], buffer[43]]),
            u32::from_le_bytes([buffer[44], buffer[45], buffer[46], buffer[47]]),
        ];

        // Done
        Some(Self {
            socket_type,
            isn,
            mss,
            flight_flag_size,
            request_type,
            id,
            cookie,
            ip,
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketType {
    Stream,
    Datagram,
}

const UDT_VERSION: u8 = 4;
const HANDSHAKE_SIZE: usize = 48;
