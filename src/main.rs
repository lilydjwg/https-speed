#![feature(let_chains, thread_sleep_until)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use eyre::Result;
use clap::Parser;
use tracing::{debug, info};

mod packet;
mod sni;
mod stat;
mod util;

use packet::Connection;
use stat::Stat;

#[derive(Parser)]
#[command(author, version, about, long_about = "show HTTPS download speed (e.g. for pacman mirrors)")]
struct Args {
  #[arg(help = "device", default_value = "any")]
  device: String,
}

struct Processor {
  connections: Arc<Mutex<HashMap<Connection, Stat>>>,
}

impl Processor {
  fn new(connections: Arc<Mutex<HashMap<Connection, Stat>>>) -> Self {
    Self {
      connections,
    }
  }

  fn process(&mut self, packet: &[u8], linktype: pcap::Linktype) {
    let (conn, tcp) = packet::tcp_from_packet(packet, linktype);
    let data = tcp.payload();
    debug!(
      ?conn, "data len={}{}{}{}", data.len(),
      if tcp.syn() { " SYN" } else { "" },
      if tcp.fin() { " FIN" } else { "" },
      if tcp.rst() { " RST" } else { "" },
    );
    let mut connections = self.connections.lock().unwrap();
    if let Some(stat) = connections.get_mut(&conn) {
      stat.incr(data.len(), conn.is_sent(), tcp.fin() || tcp.rst());
    } else if conn.is_sent() && !data.is_empty() {
      if let Some(hostname) = sni::parse_sni(data) {
        info!(%hostname, "new TLS");
        connections.insert(
          conn,
          Stat::new(String::from(hostname), data.len()),
        );
      }
    }
  }
}

fn main() -> Result<()> {
  let args = Args::parse();

  use tracing_subscriber::EnvFilter;
  use std::io::IsTerminal;

  // default RUST_LOG=warn
  let filter = EnvFilter::try_from_default_env()
    .unwrap_or_else(|_| EnvFilter::from("warn"));
  let isatty = std::io::stderr().is_terminal();
  let fmt = tracing_subscriber::fmt::fmt()
    .with_writer(std::io::stderr)
    .with_env_filter(filter)
    .with_ansi(isatty);
  if isatty {
    fmt.init();
  } else {
    fmt.without_time().init();
  }

  let connections = Arc::new(Mutex::new(HashMap::new()));
  let mut processor = Processor::new(Arc::clone(&connections));
  stat::start_ui(connections)?;

  let mut cap = pcap::Capture::from_device(args.device.as_str())?
    .immediate_mode(true).open()?;
  cap.filter("tcp port 443", true)?;
  if args.device == "any" {
    cap.set_datalink(pcap::Linktype::LINUX_SLL2)?;
  }
  let linktype = cap.get_datalink();
  loop {
    match cap.next_packet() {
      Ok(packet) => processor.process(&packet, linktype),
      Err(pcap::Error::TimeoutExpired) => { },
      Err(e) => return Err(e.into()),
    }
  }
}
