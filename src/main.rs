#![feature(iter_next_chunk)]

use std::{
    collections::HashSet,
    io::{BufReader, Bytes, Read, stdin},
    iter::Peekable,
    process::exit,
};

// Each packet is 188 bytes long
const PACKET_SIZE: usize = 188;
// Every packet begins with a “sync byte” which has hex value 0x47
const SYNC_BYTE: u8 = 0x47;

#[derive(Debug, PartialEq, Eq)]
enum Error {
    PartialPacket(usize),
    InvalidPacket,
}

#[derive(Debug, PartialEq, Eq)]
struct MPEGPacket {
    _sync: u8,
    _flags: u8,
    _pid: u16,
    _payload: Vec<u8>,
}

/// A wrapper around a stream, which could be a socket, or file
struct TSStream<Stream: Read> {
    stream: Peekable<Bytes<BufReader<Stream>>>,
    pids: HashSet<u16>,
    packet_count: usize,
}

impl<Stream: Read> Iterator for TSStream<Stream> {
    type Item = Result<MPEGPacket, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_packet()
    }
}

impl<Stream> TSStream<Stream>
where
    Stream: Read,
{
    /// Create a new `TSStream` wrapper around an underlying stream
    fn new(stream: Stream) -> Self {
        Self {
            // Buffer the stream in memory. Technically this is only really useful for files/sockets,
            // so should be fine for this usecase
            stream: BufReader::new(stream).bytes().peekable(),
            pids: HashSet::default(),
            packet_count: 0,
        }
    }

    /// Read a single packet from the provided stream
    ///
    /// NOTE: A few issues with approach:
    ///  - If we knew the size of the stream upfront, then realistically this part might not
    ///    be needed, as if the size isn't a multiple of `PACKET_SIZE`, then the first byte has
    ///    to be a partial packet... however,
    ///  - If the content is a stream, and thus we can't technically know the length, then
    ///    realistically any byte between 0..`PACKET_SIZE` - 1 could be the start of a new packet,
    ///    but because the payload can contain any possible byte, this could be rather off ...
    ///
    /// The latter approach is currently taken, as the former lead to results not consistent
    /// with the provided example inputs. It also seemed to make more sense to me (despite the
    /// downsides), as a stream seems most likely. However, it may be more accurate to take the
    /// former approach.
    fn read_packet(&mut self) -> Option<Result<MPEGPacket, Error>> {
        let start = self.stream.peek()?;

        // This is rather crude (and is very possibly not the correct approach), but
        // if the first byte isn't the SYNC_BYTE then either this packet is invalid,
        // or it's a partial packet..
        if start.as_ref().is_ok_and(|byte| *byte != SYNC_BYTE) {
            if self.packet_count > 0 {
                return Some(Err(Error::InvalidPacket));
            }

            let _ = start.iter().next();
            let mut idx = 0;
            while let Ok(byte) = self.stream.peek()? {
                if idx >= PACKET_SIZE {
                    return Some(Err(Error::InvalidPacket));
                } else if *byte == SYNC_BYTE {
                    return Some(Err(Error::PartialPacket(idx)));
                }

                idx += 1;
                let _ = self.stream.next()?;
            }

            return Some(Err(Error::InvalidPacket));
        }

        // Grab the next packet out
        let packet = self.stream.next_chunk::<PACKET_SIZE>().map_or_else(
            // If there's too little data, it's most likely this is an incomplete packet? However, for some reason,
            // this still seems to pass just fine for the examples provided...
            |e| e.flatten().collect::<Vec<_>>(),
            // Otherwise, there's enough data in the stream to work with
            |packet| {
                packet
                    .iter()
                    .flat_map(|byte| byte.as_ref().cloned())
                    .collect::<Vec<_>>()
            },
        );

        let sync = packet[0];
        if sync != SYNC_BYTE {
            return Some(Err(Error::InvalidPacket));
        }

        let flags = (packet[1] & 0xE0) >> 5;
        let pid = (u16::from(packet[1] & 0x1F) << 8) | u16::from(packet[2]);
        let payload = &packet[3..];

        let packet = MPEGPacket {
            _sync: sync,
            _flags: flags,
            _pid: pid,
            _payload: payload.to_vec(),
        };

        self.pids.insert(pid);
        self.packet_count += 1;

        Some(Ok(packet))
    }
}

fn main() {
    let mut offset = 0;

    let mut stream = TSStream::new(stdin());
    match stream.next() {
        Some(Ok(_packet)) => {
            offset += PACKET_SIZE;
        }
        Some(Err(Error::PartialPacket(off))) => {
            // Ignore the first packet if it's a partial packet
            offset += off;
        }
        Some(Err(Error::InvalidPacket)) => {
            // TODO: What should happen if the first packet is invalid? Discard it? Is it a partial packet?
            println!(
                "Error: No sync byte present in packet {}, offset {offset}",
                stream.packet_count
            );
            exit(1);
        }
        None => exit(0),
    }

    for packet in &mut stream {
        if let Ok(_packet) = packet {
            offset += PACKET_SIZE;
        } else {
            println!(
                "Error: No sync byte present in packet {}, offset {offset}",
                stream.packet_count
            );
            exit(1);
        }
    }

    let mut pids = stream.pids.iter().collect::<Vec<_>>();
    pids.sort();
    for pid in pids {
        println!("0x{pid:x}");
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashSet, io::Cursor};

    use crate::{Error, MPEGPacket, PACKET_SIZE, SYNC_BYTE, TSStream};

    #[test]
    fn single_packet() {
        let mut packet = Vec::default();
        packet.push(SYNC_BYTE);
        packet.push(0);
        packet.push(0);

        packet.extend([0u8; 185]);

        let packet = Cursor::new(&packet);

        let stream = TSStream::new(packet);
        let mut stream = stream.into_iter();
        let packet = stream.next();
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(
            Ok(MPEGPacket {
                _sync: SYNC_BYTE,
                _flags: 0,
                _pid: 0,
                _payload: vec![0u8; 185],
            }),
            packet
        );

        assert!(stream.next().is_none());
    }

    #[test]
    fn multi_packet() {
        let mut packet = Vec::default();
        packet.push(SYNC_BYTE);
        packet.push(0);
        packet.push(0);

        packet.extend([0u8; 185]);

        packet.push(SYNC_BYTE);
        packet.push(0xEF);
        packet.push(0xFF);

        packet.extend([0u8; 185]);

        let packet = Cursor::new(&packet);

        let stream = TSStream::new(packet);
        let mut stream = stream.into_iter();
        let packet = stream.next();
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(
            Ok(MPEGPacket {
                _sync: SYNC_BYTE,
                _flags: 0,
                _pid: 0,
                _payload: vec![0u8; 185],
            }),
            packet
        );

        let packet = stream.next();
        assert!(packet.is_some());
        let packet = packet.unwrap();
        assert_eq!(
            Ok(MPEGPacket {
                _sync: SYNC_BYTE,
                _flags: 0x7,
                _pid: 0xFFF,
                _payload: vec![0u8; 185],
            }),
            packet
        );

        assert!(stream.next().is_none());
    }

    #[test]
    fn test_partial_first_packet() {
        const OFFSET: usize = 180;
        let mut packet = Vec::default();
        packet.extend([0u8; OFFSET]);

        packet.push(SYNC_BYTE);
        packet.push(0xEF);
        packet.push(0xFF);

        packet.extend([0u8; 185]);

        let packet = Cursor::new(&packet);

        let stream = TSStream::new(packet);
        let mut stream = stream.into_iter();
        let packet = stream.next();
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(Err(Error::PartialPacket(OFFSET)), packet);

        let packet = stream.next();
        assert!(packet.is_some());
        let packet = packet.unwrap();
        assert_eq!(
            Ok(MPEGPacket {
                _sync: SYNC_BYTE,
                _flags: 0x7,
                _pid: 0xFFF,
                _payload: vec![0u8; 185],
            }),
            packet
        );

        assert!(stream.next().is_none());
    }

    #[test]
    fn test_success_file() {
        let packets = include_bytes!("tests/test_success.ts");

        let stream = Cursor::new(&packets);
        let mut stream = TSStream::new(stream);

        for packet in &mut stream {
            assert!(packet.is_ok());
        }

        let mut pids = HashSet::default();
        pids.extend([0x0, 0x11, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x1fff]);

        assert_eq!(stream.pids, pids)
    }

    #[test]
    fn test_failure_file() {
        let packets = include_bytes!("tests/test_failure.ts");

        let stream = Cursor::new(&packets);
        let mut stream = TSStream::new(stream);

        let mut offset = 0;

        for packet in &mut stream {
            if let Ok(_packet) = packet {
                offset += PACKET_SIZE;
            } else {
                assert_eq!(stream.packet_count, 20535);
                assert_eq!(offset, 3860580);

                return;
            }
        }

        panic!("Failed to find an invalid packet");
    }
}
