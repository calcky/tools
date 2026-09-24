use std::io;

pub const HEADER: usize = 48;
pub const MAX: usize = 65507;
pub const CONTROL: u8 = 1;
// CONTROL stamp=0 keeps the run alive until END or control-channel closure.
pub const UNLIMITED_RUN: u64 = 0;
pub const ACCEPT: u8 = 2;
pub const OPEN: u8 = 3;
pub const ACK: u8 = 4;
pub const DATA: u8 = 5;
pub const CLOSE: u8 = 6;
pub const STATS: u8 = 7;
pub const END: u8 = 8;
pub const REPORT_LEN: usize = HEADER + 8 * 8;
pub const TEARDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub tcp: bool,
    pub run: u64,
    pub flow: u64,
    pub seq: u64,
    pub stamp: u64,
    pub aux: u32,
    pub len: usize,
}

impl Header {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Overwrite `out` with this header and a zero-filled payload, reusing capacity.
    pub fn encode_into(self, out: &mut Vec<u8>) {
        out.clear();
        out.resize(self.len, 0);
        out[..4].copy_from_slice(b"FLWG");
        out[4..8].copy_from_slice(&(self.len as u32).to_be_bytes());
        out[8] = self.kind;
        out[9] = 1;
        out[10] = u8::from(self.tcp);
        out[12..20].copy_from_slice(&self.run.to_be_bytes());
        out[20..28].copy_from_slice(&self.flow.to_be_bytes());
        out[28..36].copy_from_slice(&self.seq.to_be_bytes());
        out[36..44].copy_from_slice(&self.stamp.to_be_bytes());
        out[44..48].copy_from_slice(&self.aux.to_be_bytes());
    }
}

pub fn parse(data: &[u8]) -> io::Result<Header> {
    if data.len() < HEADER
        || &data[..4] != b"FLWG"
        || data[9] != 1
        || data[10] > 1
        || data[11] != 0
        || !(CONTROL..=END).contains(&data[8])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid flowgen header",
        ));
    }
    let len = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
    if !(HEADER..=MAX).contains(&len) || data.len() != len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid flowgen length",
        ));
    }
    Ok(Header {
        kind: data[8],
        tcp: data[10] != 0,
        run: u64::from_be_bytes(data[12..20].try_into().unwrap()),
        flow: u64::from_be_bytes(data[20..28].try_into().unwrap()),
        seq: u64::from_be_bytes(data[28..36].try_into().unwrap()),
        stamp: u64::from_be_bytes(data[36..44].try_into().unwrap()),
        aux: u32::from_be_bytes(data[44..48].try_into().unwrap()),
        len,
    })
}

#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}
impl Decoder {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    #[cfg(test)]
    pub fn push(&mut self, bytes: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let mut frames = Vec::new();
        self.push_with(bytes, |frame| {
            frames.push(frame.to_vec());
            Ok(())
        })?;
        Ok(frames)
    }

    /// Deliver validated frames borrowed from `bytes` or reusable partial-frame storage.
    /// Only incomplete frames are copied into storage. Callbacks run in wire order;
    /// an error stops delivery immediately, and the decoder must then be discarded.
    pub fn push_with(
        &mut self,
        mut bytes: &[u8],
        mut callback: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if bytes.len() > MAX + 65536 - self.buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP frame buffer limit",
            ));
        }
        loop {
            if !self.buf.is_empty() {
                // Finish the length prefix before deciding how much body to buffer.
                let prefix = (8usize.saturating_sub(self.buf.len())).min(bytes.len());
                self.buf.extend_from_slice(&bytes[..prefix]);
                bytes = &bytes[prefix..];
                if self.buf.len() < 8 {
                    return Ok(());
                }
                let len = Self::frame_len(&self.buf)?;
                let body = (len - self.buf.len()).min(bytes.len());
                self.buf.extend_from_slice(&bytes[..body]);
                bytes = &bytes[body..];
                if self.buf.len() < len {
                    return Ok(());
                }
                parse(&self.buf)?;
                callback(&self.buf)?;
                self.buf.clear();
            }

            if bytes.len() < 8 {
                break;
            }
            let len = Self::frame_len(bytes)?;
            if bytes.len() < len {
                break;
            }
            let (frame, rest) = bytes.split_at(len);
            parse(frame)?;
            callback(frame)?;
            bytes = rest;
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn frame_len(bytes: &[u8]) -> io::Result<usize> {
        if &bytes[..4] != b"FLWG" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TCP magic",
            ));
        }
        let len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        if !(HEADER..=MAX).contains(&len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TCP length",
            ));
        }
        Ok(len)
    }
}

pub fn counters(frame: &[u8]) -> io::Result<[u64; 8]> {
    let h = parse(frame)?;
    if h.kind != STATS || frame.len() != REPORT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid statistics response",
        ));
    }
    let mut result = [0; 8];
    for (n, value) in result.iter_mut().enumerate() {
        *value = u64::from_be_bytes(
            frame[HEADER + n * 8..HEADER + (n + 1) * 8]
                .try_into()
                .unwrap(),
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Vec<u8> {
        Header {
            kind: DATA,
            tcp: true,
            run: 5,
            flow: 2,
            seq: 42,
            stamp: 123,
            aux: 0,
            len: 128,
        }
        .encode()
    }
    #[test]
    fn split_and_coalesced_frames() {
        let frame = sample();
        for split in 0..=frame.len() {
            let mut d = Decoder::default();
            let mut got = d.push(&frame[..split]).unwrap();
            got.extend(d.push(&frame[split..]).unwrap());
            assert_eq!(got, vec![frame.clone()]);
        }
        let mut both = frame.clone();
        both.extend(&frame);
        assert_eq!(Decoder::default().push(&both).unwrap().len(), 2);
    }
    #[test]
    fn rejects_bad_lengths_and_versions() {
        let mut b = sample();
        b[9] = 2;
        assert!(parse(&b).is_err());
        b[9] = 1;
        b[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Decoder::default().push(&b).is_err());
        assert!(parse(&sample()[..32]).is_err());
    }

    #[test]
    fn encode_into_reuses_capacity_and_clears_old_bytes() {
        let mut header = parse(&sample()).unwrap();
        let mut out = vec![0xff; 256];
        let allocation = out.as_ptr();
        let capacity = out.capacity();
        for len in [128, HEADER, 256, 64] {
            out.fill(0xff);
            header.len = len;
            header.tcp = !header.tcp;
            header.seq += 1;
            header.aux += 1;
            header.encode_into(&mut out);
            assert_eq!(out.as_ptr(), allocation);
            assert_eq!(out.capacity(), capacity);
            assert_eq!(out.len(), len);
            assert_eq!(parse(&out).unwrap(), header);
            assert_eq!(out[11], 0);
            assert!(out[HEADER..].iter().all(|&byte| byte == 0));
            assert_eq!(out, header.encode());
        }
        let mut empty = Vec::new();
        header.encode_into(&mut empty);
        assert_eq!(empty, header.encode());
    }

    #[test]
    fn borrowed_frames_survive_every_split_and_chunk_size() {
        let mut header = parse(&sample()).unwrap();
        let frames: Vec<_> = [HEADER, 128, 257]
            .into_iter()
            .map(|len| {
                header.len = len;
                header.seq += 1;
                header.encode()
            })
            .collect();
        let stream = frames.concat();
        for split in 0..=stream.len() {
            let mut d = Decoder::default();
            let mut got = Vec::new();
            for bytes in [&stream[..split], &stream[split..]] {
                d.push_with(bytes, |frame| {
                    got.push(frame.to_vec());
                    Ok(())
                })
                .unwrap();
            }
            assert_eq!(got, frames, "split {split}");
            assert!(d.buf.is_empty());
        }
        for size in 1..=stream.len() {
            let mut d = Decoder::default();
            let mut got = Vec::new();
            for bytes in stream.chunks(size) {
                d.push_with(bytes, |frame| {
                    got.push(frame.to_vec());
                    Ok(())
                })
                .unwrap();
            }
            assert_eq!(got, frames, "chunk size {size}");
            assert!(d.buf.is_empty());
        }
    }

    #[test]
    fn complete_frames_borrow_input_without_buffer_allocation() {
        let frame = sample();
        let stream = [frame.clone(), frame.clone()].concat();
        let mut d = Decoder::default();
        let mut count = 0;
        d.push_with(&stream, |got| {
            assert_eq!(got, frame);
            assert_eq!(got.as_ptr(), stream[count * frame.len()..].as_ptr());
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 2);
        assert_eq!(d.buf.capacity(), 0);
    }

    #[test]
    fn partial_storage_is_reused_and_following_frames_borrow_input() {
        let frame = sample();
        let stream = [frame.clone(), frame.clone(), frame.clone()].concat();
        let mut d = Decoder::with_capacity(frame.len());
        let allocation = d.buf.as_ptr();
        for _ in 0..2 {
            d.push_with(&stream[..3], |_| panic!("incomplete prefix"))
                .unwrap();
            let mut count = 0;
            d.push_with(&stream[3..stream.len() - 5], |got| {
                assert_eq!(got, frame);
                assert_eq!(
                    got.as_ptr(),
                    if count == 0 {
                        allocation
                    } else {
                        stream[frame.len()..].as_ptr()
                    }
                );
                count += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(count, 2);
            assert_eq!(d.buf.len(), frame.len() - 5);
            // The compatibility wrapper can finish a borrowed decoder's partial frame.
            assert_eq!(
                d.push(&stream[stream.len() - 5..]).unwrap(),
                vec![frame.clone()]
            );
            assert_eq!(d.buf.as_ptr(), allocation);
        }
    }

    #[test]
    fn borrowed_decoder_rejects_invalid_prefixes_when_complete() {
        let mut invalid = Vec::new();
        let mut magic = sample();
        magic[0] = b'X';
        invalid.push(magic);
        for len in [0, HEADER as u32 - 1, MAX as u32 + 1, u32::MAX] {
            let mut frame = sample();
            frame[4..8].copy_from_slice(&len.to_be_bytes());
            invalid.push(frame);
        }
        for frame in invalid {
            for split in 0..8 {
                let mut d = Decoder::default();
                d.push_with(&frame[..split], |_| panic!("invalid prefix"))
                    .unwrap();
                let err = d
                    .push_with(&frame[split..], |_| panic!("invalid frame"))
                    .unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[test]
    fn borrowed_decoder_validates_headers_before_delivery() {
        let valid = sample();
        for (offset, value) in [(8, 0), (8, END + 1), (9, 2), (10, 2), (11, 1)] {
            let mut invalid = valid.clone();
            invalid[offset] = value;
            for split in 0..invalid.len() {
                let mut d = Decoder::default();
                d.push_with(&invalid[..split], |_| panic!("incomplete frame"))
                    .unwrap();
                let err = d
                    .push_with(&invalid[split..], |_| panic!("invalid header"))
                    .unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            }
            let stream = [valid.clone(), invalid, valid.clone()].concat();
            let mut count = 0;
            let err = Decoder::default()
                .push_with(&stream, |_| {
                    count += 1;
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(count, 1);
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(Decoder::default().push(&stream).is_err());
        }
    }

    #[test]
    fn callback_error_stops_coalesced_delivery() {
        let stream = [sample(), sample()].concat();
        for split in [0, 1, 8, HEADER] {
            let mut d = Decoder::default();
            d.push_with(&stream[..split], |_| panic!("incomplete frame"))
                .unwrap();
            let mut count = 0;
            let err = d
                .push_with(&stream[split..], |_| {
                    count += 1;
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "callback failed"))
                })
                .unwrap_err();
            assert_eq!(count, 1);
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(err.to_string(), "callback failed");
        }
    }

    #[test]
    fn borrowed_decoder_preserves_buffer_limit_including_partial_bytes() {
        let mut header = parse(&sample()).unwrap();
        header.len = MAX;
        let frame = header.encode();
        let mut stream = [frame.clone(), frame].concat();
        let tail = sample();
        let tail_len = MAX + 65536 - stream.len();
        stream.extend_from_slice(&tail[..tail_len]);
        for split in [0, 7, HEADER] {
            let mut d = Decoder::default();
            d.push_with(&stream[..split], |_| panic!("incomplete frame"))
                .unwrap();
            let mut oversized = stream[split..].to_vec();
            oversized.push(0);
            let err = d
                .push_with(&oversized, |_| panic!("over limit"))
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "TCP frame buffer limit");
            assert_eq!(d.buf, stream[..split]);

            // The size guard rejects input before changing the existing partial frame.
            let mut count = 0;
            d.push_with(&stream[split..], |got| {
                assert_eq!(got.len(), MAX);
                count += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(count, 2);
            assert_eq!(d.buf, tail[..tail_len]);
            assert_eq!(d.push(&tail[tail_len..]).unwrap(), vec![tail.clone()]);
        }
    }
}
