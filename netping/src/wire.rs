use std::io;
pub const HEADER: usize = 32;
pub const MAX: usize = 65507;
const MAGIC: &[u8; 4] = b"NPNG";
const TCP_REQUEST: &[u8; 4] = b"RTQ1";
const TCP_REPLY: &[u8; 4] = b"RTR1";
const MSS_REQUEST: &[u8; 4] = b"MSQ1";
const MSS_REPLY: &[u8; 4] = b"MSR1";
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub session: u64,
    pub seq: u64,
    pub reply: bool,
    pub retrans: Option<u32>,
    pub mtu_size: Option<usize>,
}
pub fn encode(session: u64, seq: u64, size: usize) -> Vec<u8> {
    let mut b = vec![0; size];
    b[..4].copy_from_slice(MAGIC);
    b[4] = 1;
    b[8..16].copy_from_slice(&session.to_be_bytes());
    b[16..24].copy_from_slice(&seq.to_be_bytes());
    b[24..28].copy_from_slice(&(size as u32).to_be_bytes());
    b
}
pub fn parse(b: &[u8]) -> Option<Message> {
    if !(HEADER..=MAX).contains(&b.len())
        || &b[..4] != MAGIC
        || b[4] != 1
        || b[5] > 1
        || b[6] > 2
        || b[7] != 0
    {
        return None;
    }
    if u32::from_be_bytes(b[24..28].try_into().ok()?) as usize != b.len() {
        return None;
    }
    let original = u32::from_be_bytes(b[28..32].try_into().ok()?) as usize;
    let mtu_size = match b[6] {
        0 if original == 0 => None,
        1 if b[5] == 0 && original == 0 => Some(b.len()),
        2 if b[5] == 1 && b.len() == HEADER && (HEADER..=MAX).contains(&original) => Some(original),
        _ => return None,
    };
    let m = Message {
        session: u64::from_be_bytes(b[8..16].try_into().ok()?),
        seq: u64::from_be_bytes(b[16..24].try_into().ok()?),
        reply: b[5] == 1,
        retrans: (b[5] == 1 && b.len() >= HEADER + 8 && &b[HEADER..HEADER + 4] == TCP_REPLY)
            .then(|| u32::from_be_bytes(b[HEADER + 4..HEADER + 8].try_into().unwrap())),
        mtu_size,
    };
    (m.session != 0 && m.seq != 0).then_some(m)
}
pub fn reply(b: &mut [u8]) -> bool {
    if parse(b).is_some_and(|m| !m.reply && m.mtu_size.is_none()) {
        b[5] = 1;
        true
    } else {
        false
    }
}

pub fn mtu_request(session: u64, seq: u64, size: usize) -> Vec<u8> {
    let mut b = encode(session, seq, size);
    b[6] = 1;
    b
}

pub fn reply_udp(b: &mut [u8]) -> Option<usize> {
    let m = parse(b).filter(|m| !m.reply)?;
    if let Some(size) = m.mtu_size {
        b[5] = 1;
        b[6] = 2;
        b[24..28].copy_from_slice(&(HEADER as u32).to_be_bytes());
        b[28..32].copy_from_slice(&(size as u32).to_be_bytes());
        Some(HEADER)
    } else {
        b[5] = 1;
        Some(b.len())
    }
}

pub fn request_tcp_info(b: &mut [u8]) {
    if b.len() >= HEADER + 8 {
        b[HEADER..HEADER + 4].copy_from_slice(TCP_REQUEST);
    }
}

pub fn request_mss(b: &mut [u8]) {
    if b.len() >= HEADER + 8 {
        b[HEADER..HEADER + 4].copy_from_slice(MSS_REQUEST);
        b[HEADER + 4..HEADER + 8].fill(0);
    }
}

pub fn requests_mss(b: &[u8]) -> bool {
    b.len() >= HEADER + 8 && &b[HEADER..HEADER + 4] == MSS_REQUEST
}

pub fn report_mss(b: &mut [u8], send_mss: Option<u32>) {
    if requests_mss(b) && parse(b).is_some_and(|m| m.reply && m.mtu_size.is_none()) {
        b[HEADER..HEADER + 4].copy_from_slice(MSS_REPLY);
        b[HEADER + 4..HEADER + 8].copy_from_slice(&send_mss.unwrap_or(0).to_be_bytes());
    }
}

// None is an old echo peer; Some(None) is a peer with unavailable kernel data.
pub fn peer_mss(b: &[u8]) -> Option<Option<u32>> {
    if b.len() < HEADER + 8 || &b[HEADER..HEADER + 4] != MSS_REPLY {
        return None;
    }
    let value = u32::from_be_bytes(b[HEADER + 4..HEADER + 8].try_into().unwrap());
    Some((1..=65535).contains(&value).then_some(value))
}

pub fn reply_tcp(b: &mut [u8], retrans: Option<u32>) -> bool {
    if !reply(b) {
        return false;
    }
    // Opt in through payload bytes so v1 peers still echo the same frame size.
    if let Some(retrans) = retrans {
        if b.len() >= HEADER + 8 && &b[HEADER..HEADER + 4] == TCP_REQUEST {
            b[HEADER..HEADER + 4].copy_from_slice(TCP_REPLY);
            b[HEADER + 4..HEADER + 8].copy_from_slice(&retrans.to_be_bytes());
        }
    }
    true
}
pub fn frame(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(b.len() + 4);
    v.extend_from_slice(&(b.len() as u32).to_be_bytes());
    v.extend_from_slice(b);
    v
}
#[derive(Default)]
pub struct Decoder {
    data: Vec<u8>,
}
impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        self.data.extend_from_slice(bytes);
        let mut offset = 0;
        let mut frames = Vec::new();
        while self.data.len() - offset >= 4 {
            let len =
                u32::from_be_bytes(self.data[offset..offset + 4].try_into().unwrap()) as usize;
            if !(HEADER..=MAX).contains(&len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid TCP frame length",
                ));
            }
            if self.data.len() - offset < 4 + len {
                break;
            }
            frames.push(self.data[offset + 4..offset + 4 + len].to_vec());
            offset += 4 + len;
        }
        self.data.drain(..offset);
        Ok(frames)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mss_telemetry_is_opt_in_and_old_echoes_are_not_reports() {
        for size in [32, 39, 40, 64] {
            let mut request = encode(42, 7, size);
            request_mss(&mut request);
            let mut legacy = request.clone();
            assert!(reply_tcp(&mut legacy, Some(123)));
            assert_eq!(peer_mss(&legacy), None);
            assert!(reply_tcp(&mut request, Some(123)));
            report_mss(&mut request, Some(1388));
            assert_eq!(request.len(), size);
            assert_eq!(peer_mss(&request), (size >= 40).then_some(Some(1388)));
            assert_eq!(parse(&request).unwrap().retrans, None);
        }
        let mut old_client = encode(42, 1, 64);
        assert!(reply_tcp(&mut old_client, Some(123)));
        report_mss(&mut old_client, Some(1388));
        assert_eq!(peer_mss(&old_client), None);
        let mut unavailable = encode(42, 1, 64);
        request_mss(&mut unavailable);
        assert!(reply(&mut unavailable));
        report_mss(&mut unavailable, None);
        assert_eq!(peer_mss(&unavailable), Some(None));
    }
    #[test]
    fn mtu_ack_is_small_and_preserves_original_size_without_changing_echo() {
        for size in [32, 64, 1400, MAX] {
            let mut b = mtu_request(42, 7, size);
            assert_eq!(parse(&b).unwrap().mtu_size, Some(size));
            assert!(!reply(&mut b));
            assert!(!reply_tcp(&mut b, Some(4)));
            let len = reply_udp(&mut b).unwrap();
            assert_eq!(len, HEADER);
            let m = parse(&b[..len]).unwrap();
            assert_eq!(
                (m.session, m.seq, m.reply, m.mtu_size),
                (42, 7, true, Some(size))
            );
            assert_eq!(reply_udp(&mut b[..len]), None);
            let mut normal = encode(42, 7, size);
            assert_eq!(reply_udp(&mut normal), Some(size));
            assert!(parse(&normal).unwrap().mtu_size.is_none());
        }
        let mut b = mtu_request(42, 7, 64);
        b[5] = 1;
        assert!(parse(&b).is_none());
        b[6] = 2;
        assert!(parse(&b).is_none());
    }
    #[test]
    fn protocol_rejects_invalid_messages() {
        let mut b = encode(42, 7, 64);
        assert_eq!(
            parse(&b),
            Some(Message {
                session: 42,
                seq: 7,
                reply: false,
                retrans: None,
                mtu_size: None,
            })
        );
        assert!(reply(&mut b));
        assert!(!reply(&mut b));
        assert!(parse(&b).unwrap().reply);
        for i in [0, 4, 5, 6, 24, 28] {
            let mut x = b.clone();
            x[i] = 255;
            assert!(parse(&x).is_none());
        }
        assert!(parse(&b[..31]).is_none());
        assert!(parse(&encode(0, 1, 32)).is_none());
    }
    #[test]
    fn tcp_reports_are_opt_in_and_preserve_legacy_and_short_echoes() {
        for size in [32, 39, 40, 64] {
            let original = encode(42, 7, size);
            let mut request = original.clone();
            request_tcp_info(&mut request);
            assert_eq!(request.len(), size);
            assert!(parse(&request).is_some());
            assert_eq!(parse(&request).unwrap().retrans, None);
            let mut legacy = request.clone();
            assert!(reply(&mut legacy));
            assert_eq!(parse(&legacy).unwrap().retrans, None);
            assert!(reply_tcp(&mut request, Some(123)));
            assert_eq!(
                parse(&request).unwrap().retrans,
                (size >= 40).then_some(123)
            );
            assert!(!reply_tcp(&mut request, Some(999)));
            let mut old_client = original;
            assert!(reply_tcp(&mut old_client, Some(123)));
            assert_eq!(parse(&old_client).unwrap().retrans, None);
        }
    }
    #[test]
    fn framing_handles_all_splits_and_coalescing() {
        let b = encode(1, 1, 64);
        let f = frame(&b);
        for split in 0..f.len() {
            let mut d = Decoder::default();
            assert!(d.push(&f[..split]).unwrap().is_empty());
            assert_eq!(d.push(&f[split..]).unwrap(), vec![b.clone()]);
        }
        let mut d = Decoder::default();
        assert_eq!(d.push(&[f.clone(), f].concat()).unwrap().len(), 2);
        assert!(d.push(&u32::MAX.to_be_bytes()).is_err());
    }
}
