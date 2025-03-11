#![feature(bufreader_peek, iter_next_chunk)]

use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Read, stdin},
    process::exit,
};

// Each packet is 188 bytes long
const PACKET_SIZE: usize = 188;
// Every packet begins with a “sync byte” which has hex value 0x47
const SYNC_BYTE: u8 = 0x47;

#[derive(Debug, PartialEq, Eq)]
enum ParseError {
    PartialPacket(usize),
    InvalidPacket,
}

#[derive(Debug, PartialEq, Eq)]
struct Packet {
    _sync: u8,
    _flags: u8,
    pid: u16,
    _payload: Vec<u8>,
}

impl Packet {
    fn parse_from_stream<Reader: Read>(
        stream: &mut TransportStream<Reader>,
    ) -> Result<Self, ParseError> {
        let mut packet = [0u8; PACKET_SIZE];
        let _ = stream.read(&mut packet);

        let sync = packet[0];
        if sync != SYNC_BYTE {
            return Err(ParseError::InvalidPacket);
        }

        let flags = (packet[1] & 0xE0) >> 5;
        let pid = (u16::from(packet[1] & 0x1F) << 8) | u16::from(packet[2]);
        let payload = &packet[3..];

        let packet = Self {
            _sync: sync,
            _flags: flags,
            pid,
            _payload: payload.to_vec(),
        };

        Ok(packet)
    }
}

/// A wrapper around a stream, which could be a socket, or file
struct TransportStream<Reader: Read> {
    buffer: BufReader<Reader>,
    pids: HashSet<u16>,
    packet_count: usize,
}

impl<Reader> Iterator for TransportStream<Reader>
where
    Reader: Read,
{
    type Item = Result<Packet, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_packet()
    }
}

impl<Reader> TransportStream<Reader>
where
    Reader: Read,
{
    fn from_reader(reader: Reader) -> Self {
        let mut buffer = BufReader::with_capacity(PACKET_SIZE * 4, reader);
        let _ = buffer.fill_buf();
        Self {
            buffer,
            pids: HashSet::default(),
            packet_count: 0,
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.get(0)
    }

    fn next_byte(&mut self) -> u8 {
        let mut buf = [0u8; 1];
        let _ = self.buffer.read(&mut buf[..]);
        buf[0]
    }

    fn get(&mut self, at: usize) -> Option<u8> {
        match self.buffer.peek(at + 1) {
            Err(_) | Ok(&[]) => None,
            Ok(bytes) if bytes.len() < at + 1 => None,
            Ok(&[.., byte]) => Some(byte),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.buffer.read_exact(&mut buf[..])
    }

    /// If we've found a sync byte, then if another sync byte exists
    /// exactly 1 packet away, and another two exist (or there's not
    /// enough data) at `PACKET_SIZE` offsets, then we can assume
    /// that we are at a sync byte for the start of a new packet
    fn at_starting_sync_byte(&mut self) -> bool {
        self.get(PACKET_SIZE).is_none_or(|b| b == SYNC_BYTE)
            && self.get(PACKET_SIZE * 2).is_none_or(|b| b == SYNC_BYTE)
            && self.get(PACKET_SIZE * 3).is_none_or(|b| b == SYNC_BYTE)
    }

    /// Read a single packet from the provided stream
    ///
    /// NOTE: This uses a basic heuristic to check for partial packets.
    fn read_packet(&mut self) -> Option<Result<Packet, ParseError>> {
        let byte = self.peek()?;

        // This is rather crude (and is very possibly not the correct approach), but
        // if the first byte isn't the SYNC_BYTE then either this packet is invalid,
        // or it's a partial packet..
        if byte != SYNC_BYTE {
            self.next_byte(); // Ignore the first one, as we peeked it earlier

            // Only look up to 1 packet away
            for idx in 1..PACKET_SIZE {
                if self.peek()? == SYNC_BYTE && self.at_starting_sync_byte() {
                    // Assume that this is the proper start of the next packet
                    return Some(Err(ParseError::PartialPacket(idx)));
                }

                self.next_byte();
            }

            // Otherwise, we can't find an obvious starting point, so it's invalid
            return Some(Err(ParseError::InvalidPacket));
        }

        // Grab the next packet out
        let packet = Packet::parse_from_stream(self);

        if let Ok(ref packet) = packet {
            self.pids.insert(packet.pid);
            self.packet_count += 1;
        }

        Some(packet)
    }
}

fn main() {
    let mut offset = 0;

    let mut stream = TransportStream::from_reader(stdin());

    match stream.next() {
        Some(Ok(_packet)) => {
            offset += PACKET_SIZE;
        }
        Some(Err(ParseError::PartialPacket(off))) => {
            // Ignore the first packet if it's a partial packet
            offset += off;
        }
        Some(Err(ParseError::InvalidPacket)) => {
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

    use crate::{PACKET_SIZE, Packet, ParseError, SYNC_BYTE, TransportStream};

    #[test]
    fn single_packet() {
        let mut packet = Vec::default();
        packet.push(SYNC_BYTE);
        packet.push(0);
        packet.push(0);

        packet.extend([0u8; 185]);

        let packet = Cursor::new(&packet);

        let stream = TransportStream::from_reader(packet);
        let mut stream = stream.into_iter();
        let packet = stream.next();
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(
            Ok(Packet {
                _sync: SYNC_BYTE,
                _flags: 0,
                pid: 0,
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

        let stream = TransportStream::from_reader(packet);
        let mut stream = stream.into_iter();
        let packet = stream.next();
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(
            Ok(Packet {
                _sync: SYNC_BYTE,
                _flags: 0,
                pid: 0,
                _payload: vec![0u8; 185],
            }),
            packet
        );

        let packet = stream.next();
        assert!(packet.is_some());
        let packet = packet.unwrap();
        assert_eq!(
            Ok(Packet {
                _sync: SYNC_BYTE,
                _flags: 0x7,
                pid: 0xFFF,
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

        packet.push(SYNC_BYTE);
        packet.push(0xEF);
        packet.push(0xFF);

        packet.extend([0u8; 185]);

        packet.push(SYNC_BYTE);
        packet.push(0xEF);
        packet.push(0xFF);

        packet.extend([0u8; 185]);

        packet.push(SYNC_BYTE);
        packet.push(0xEF);
        packet.push(0xFF);

        packet.extend([0u8; 185]);

        let packet = Cursor::new(&packet);

        let stream = TransportStream::from_reader(packet);
        let mut stream = stream.into_iter();
        let packet = stream.next();
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(Err(ParseError::PartialPacket(OFFSET)), packet);

        let packet = stream.next();
        assert!(packet.is_some());
        let packet = packet.unwrap();
        assert_eq!(
            Ok(Packet {
                _sync: SYNC_BYTE,
                _flags: 0x7,
                pid: 0xFFF,
                _payload: vec![0u8; 185],
            }),
            packet
        );
    }

    #[test]
    fn test_success_file() {
        let packets = include_bytes!("tests/test_success.ts");

        let stream = Cursor::new(&packets);
        let mut stream = TransportStream::from_reader(stream);

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
        let mut stream = TransportStream::from_reader(stream);

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
