#![feature(iter_next_chunk)]

use std::{
    collections::HashSet,
    io::{Read, stdin},
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
struct MPEGPacket {
    _sync: u8,
    _flags: u8,
    pid: u16,
    _payload: Vec<u8>,
}

impl MPEGPacket {
    fn parse_from_stream(stream: &TransportStream) -> Result<Self, ParseError> {
        let packet = stream.get_range::<PACKET_SIZE>();

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
struct TransportStream {
    buffer: Vec<u8>,
    cursor: usize,
    pids: HashSet<u16>,
    packet_count: usize,
}

impl Iterator for TransportStream {
    type Item = Result<MPEGPacket, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_packet()
    }
}

impl TransportStream {
    fn from_reader<Reader>(mut reader: Reader) -> std::io::Result<Self>
    where
        Reader: Read,
    {
        // This could probably be held in some sort of temporary buffer that's smaller,
        // or can be made to hold only a specific capacity in order to keep memory footprint
        // down, as well as make it more suitable to streaming the content in, but for
        // simplicity's sake this works fine
        let mut buffer = Vec::default();
        reader.read_to_end(&mut buffer)?;

        Ok(Self {
            buffer,
            cursor: 0,
            pids: HashSet::default(),
            packet_count: 0,
        })
    }

    fn peek(&self) -> Option<u8> {
        if self.cursor >= self.buffer.len() {
            None
        } else {
            Some(self.buffer[self.cursor])
        }
    }

    fn next_byte(&mut self) -> u8 {
        let byte = self.buffer[self.cursor];
        self.cursor += 1;
        byte
    }

    fn get(&self, at: usize) -> Option<u8> {
        if self.buffer.len() <= at {
            None
        } else {
            Some(self.buffer[at])
        }
    }

    fn get_range<const N: usize>(&self) -> &[u8] {
        // TODO: Figure out why the provided success file actually doesn't
        // contain a multiple of `PACKET_SIZE` packets ...
        let end = std::cmp::min(self.cursor + N, self.buffer.len());
        &self.buffer[self.cursor..end]
    }

    /// Read a single packet from the provided stream
    ///
    /// NOTE: This uses a basic heuristic to check for partial packets.
    fn read_packet(&mut self) -> Option<Result<MPEGPacket, ParseError>> {
        let byte = self.peek()?;

        // This is rather crude (and is very possibly not the correct approach), but
        // if the first byte isn't the SYNC_BYTE then either this packet is invalid,
        // or it's a partial packet..
        if byte != SYNC_BYTE {
            self.next_byte(); // Ignore the first one, as we peeked it earlier

            // Only look up to 1 packet away
            for _ in 0..PACKET_SIZE {
                if self.peek()? == SYNC_BYTE
                        // If we've found a sync byte, then if another sync byte exists
                        // exactly 1 packet away, ...
                        && self
                            .get(self.cursor + PACKET_SIZE)
                            .is_some_and(|b| b == SYNC_BYTE)
                        // and another two exist (or there's not enough data) at `PACKET_SIZE`
                        // offsets ...
                        && self
                            .get(self.cursor + PACKET_SIZE * 2)
                            .is_none_or(|b| b == SYNC_BYTE)
                        && self
                            .get(self.cursor + PACKET_SIZE * 3)
                            .is_none_or(|b| b == SYNC_BYTE)
                {
                    // Then basically assume that this is the proper start of the next packet
                    return Some(Err(ParseError::PartialPacket(self.cursor)));
                }

                self.next_byte();
            }

            // Otherwise, we can't find an obvious starting point, so it's invalid
            return Some(Err(ParseError::InvalidPacket));
        }

        // Grab the next packet out
        let packet = MPEGPacket::parse_from_stream(self);

        if let Ok(ref packet) = packet {
            self.pids.insert(packet.pid);
            self.packet_count += 1;
        }

        self.cursor += PACKET_SIZE;

        Some(packet)
    }
}

fn main() {
    let mut offset = 0;

    let mut stream =
        TransportStream::from_reader(stdin()).expect("Unable to create TransportStream");

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

    use crate::{MPEGPacket, PACKET_SIZE, ParseError, SYNC_BYTE, TransportStream};

    #[test]
    fn single_packet() {
        let mut packet = Vec::default();
        packet.push(SYNC_BYTE);
        packet.push(0);
        packet.push(0);

        packet.extend([0u8; 185]);

        let packet = Cursor::new(&packet);

        let stream = TransportStream::from_reader(packet).unwrap();
        let mut stream = stream.into_iter();
        let packet = stream.next();
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(
            Ok(MPEGPacket {
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

        let stream = TransportStream::from_reader(packet).unwrap();
        let mut stream = stream.into_iter();
        let packet = stream.next();
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(
            Ok(MPEGPacket {
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
            Ok(MPEGPacket {
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

        let stream = TransportStream::from_reader(packet).unwrap();
        let mut stream = stream.into_iter();
        let packet = stream.next();
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(Err(ParseError::PartialPacket(OFFSET)), packet);

        let packet = stream.next();
        assert!(packet.is_some());
        let packet = packet.unwrap();
        assert_eq!(
            Ok(MPEGPacket {
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
        let mut stream = TransportStream::from_reader(stream).unwrap();

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
        let mut stream = TransportStream::from_reader(stream).unwrap();

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
