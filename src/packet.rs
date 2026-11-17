use std::io;

pub(crate) const QUIC_MTU: usize = 1200;
const HEADER: usize = 28;
const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [10, 0, 0, 2];
const PORT: [u8; 2] = 4433u16.to_be_bytes();

// These internal addresses never enter the OS routing table. Every peer has its own namespace.
pub(crate) fn wrap(data: &[u8], client: bool) -> io::Result<Vec<u8>> {
    if data.len() > QUIC_MTU {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC datagram exceeds tunnel MTU",
        ));
    }
    let mut packet = vec![0; HEADER + data.len()];
    packet[0] = 0x45;
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet[6] = 0x40; // Don't fragment.
    packet[8] = 64;
    packet[9] = 17;
    let (src, dst) = if client {
        (CLIENT, SERVER)
    } else {
        (SERVER, CLIENT)
    };
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    let checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&PORT);
    packet[22..24].copy_from_slice(&PORT);
    packet[24..26].copy_from_slice(&((data.len() + 8) as u16).to_be_bytes());
    // An omitted UDP checksum is permitted by IPv4; WireGuard authenticates the whole packet.
    packet[HEADER..].copy_from_slice(data);
    Ok(packet)
}

pub(crate) fn unwrap(packet: &[u8], client: bool) -> io::Result<&[u8]> {
    let (src, dst) = if client {
        (SERVER, CLIENT)
    } else {
        (CLIENT, SERVER)
    };
    if packet.len() < HEADER
        || packet[0] != 0x45
        || packet[9] != 17
        || packet[6..8] != [0x40, 0]
        || packet[12..16] != src
        || packet[16..20] != dst
        || packet[20..22] != PORT
        || packet[22..24] != PORT
        || checksum(&packet[..20]) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid internal IP/UDP packet",
        ));
    }
    let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let udp_len = u16::from_be_bytes([packet[24], packet[25]]) as usize;
    if len != packet.len() || len > HEADER + QUIC_MTU || udp_len != len - 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid internal packet length",
        ));
    }
    Ok(&packet[HEADER..])
}

fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_be_bytes([p[0], p[1]]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
