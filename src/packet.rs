use std::net::{SocketAddr, IpAddr};
use std::hash::{Hash, Hasher};
use std::cmp::{PartialEq, Eq};
use std::io::Cursor;

use smoltcp::wire::{
  EthernetFrame, EthernetProtocol,
  Ipv4Packet,
  Ipv6Packet,
  TcpPacket,
};
use pcap::Linktype;
use byteorder::{NetworkEndian, ReadBytesExt};

#[derive(Debug)]
pub struct Connection {
  client: SocketAddr,
  server: SocketAddr,
  is_sent: bool,
}

impl Connection {
  pub fn is_sent(&self) -> bool {
    self.is_sent
  }
}

impl Hash for Connection {
  fn hash<H>(&self, state: &mut H) where H: Hasher {
    self.client.hash(state);
    self.server.hash(state);
  }
}

impl PartialEq for Connection {
  fn eq(&self, other: &Self) -> bool {
    self.client == other.client
      && self.server == other.server
  }
}

impl Eq for Connection {}

pub fn tcp_from_packet(packet: &[u8], linktype: Linktype) -> (Connection, TcpPacket<&[u8]>) {
  match linktype {
    Linktype::ETHERNET => {
      let ether = EthernetFrame::new_checked(packet).unwrap();
      ether_to_tcp(ether.payload(), ether.ethertype())
    }
    Linktype::LINUX_SLL2 => {
      let proto = Cursor::new(packet).read_u16::<NetworkEndian>().unwrap();
      ether_to_tcp(&packet[20..], proto.into())
    }
    _ => {
      panic!("unsupported datalink type: {:?}", linktype);
    }

  }
}

fn ether_to_tcp(packet: &[u8], ethertype: EthernetProtocol) -> (Connection, TcpPacket<&[u8]>) {
  let (src, dst, payload) = match ethertype {
    EthernetProtocol::Ipv4 => {
      let ip = Ipv4Packet::new_checked(packet).unwrap();
      let src = IpAddr::V4(ip.src_addr().into());
      let dst = IpAddr::V4(ip.dst_addr().into());
      (src, dst, ip.payload())
    },
    EthernetProtocol::Ipv6 => {
      let ip = Ipv6Packet::new_checked(packet).unwrap();
      let src = IpAddr::V6(ip.src_addr().into());
      let dst = IpAddr::V6(ip.dst_addr().into());
      (src, dst, ip.payload())
    },
    ty => {
      panic!("not ipv4 or ipv6 packet: {}", ty);
    }
  };
  let tcp = TcpPacket::new_checked(payload).unwrap();
  let src = SocketAddr::new(src, tcp.src_port());
  let dst = SocketAddr::new(dst, tcp.dst_port());
  let conn = if tcp.dst_port() == 443 {
    Connection {
      client: src,
      server: dst,
      is_sent: true,
    }
  } else {
    Connection {
      client: dst,
      server: src,
      is_sent: false,
    }
  };
  (conn, tcp)
}
