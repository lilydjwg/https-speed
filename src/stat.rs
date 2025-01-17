pub struct Stat {
  hostname: String,
  sent: usize,
  received: usize,
  total_sent: usize,
  total_received: usize,
  last: bool,
  stall_count: usize,
}

impl Stat {
  pub fn new(hostname: String, hello_len: usize) -> Self {
    Self {
      hostname,
      sent: hello_len,
      received: 0,
      total_sent: hello_len,
      total_received: 0,
      last: false,
      stall_count: 0,
    }
  }

  pub fn incr(&mut self, n: usize, is_sent: bool, last: bool) {
    if is_sent {
      self.sent += n;
      self.total_sent += n;
    } else {
      self.received += n;
      self.total_received += n;
    }
    self.last = self.last || last;
  }
}

#[derive(Default)]
struct PureStat {
  sent: usize,
  received: usize,
  total_sent: usize,
  total_received: usize,
}

impl std::ops::Add<&Stat> for PureStat {
  type Output = PureStat;
  fn add(self, rhs: &Stat) -> Self::Output {
    Self {
      sent: self.sent + rhs.sent,
      received: self.received + rhs.received,
      total_sent: self.total_sent + rhs.total_sent,
      total_received: self.total_received + rhs.total_received,
    }
  }
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};
use std::thread::{sleep_until, Builder};
use std::io::{self, Write};

use termion::raw::IntoRawMode;

use crate::packet::Connection;
use crate::util::Filesize;

pub fn start_ui(connections: Arc<Mutex<HashMap<Connection, Stat>>>) -> io::Result<()> {
  Builder::new()
    .name(String::from("stat-loop"))
    .spawn(move || stat_loop(connections))?;
  Ok(())
}

fn stat_loop(connections: Arc<Mutex<HashMap<Connection, Stat>>>) {
  let dur = Duration::from_secs(1);
  let mut now = Instant::now();

  let mut winch = signalbool::SignalBool::new(
    &[signalbool::Signal::SIGWINCH], signalbool::Flag::Restart,
  ).unwrap();

  let mut buffer = Vec::new();
  let mut max_y = 0;
  let mut cols = termion::terminal_size().unwrap().0 as usize;
  let mut stdout = std::io::stdout().into_raw_mode().unwrap();
  stdout.write_all(termion::clear::All.as_ref()).unwrap();
  stdout.write_all(termion::cursor::Hide.as_ref()).unwrap();
  stdout.flush().unwrap();

  unsafe {
    let flags = libc::fcntl(0, libc::F_GETFL, 0);
    libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK);
  }

  loop {
    sleep_until(now + dur);
    now = Instant::now();
    update_stats(&connections, &mut buffer, cols, &mut max_y);
    buffer.clear();
    let (ctrl_c, ctrl_l) = read_stdin();
    if ctrl_c {
      let mut stdout = std::io::stdout();
      stdout.write_all(termion::cursor::Show.as_ref()).unwrap();
      stdout.write_all(b"\x1b[1;1H").unwrap();
      stdout.flush().unwrap();
      unsafe {
        libc::kill(libc::getpid(), libc::SIGINT);
      }
    } else if ctrl_l || winch.caught() {
      cols = termion::terminal_size().unwrap().0 as usize;
      buffer.extend_from_slice(termion::clear::All.as_ref());
      winch.reset();
    }
  }
}

fn update_stats(
  connections: &Arc<Mutex<HashMap<Connection, Stat>>>,
  buffer: &mut Vec<u8>,
  cols: usize,
  last_y: &mut usize,
) {
  let target_width = cols.saturating_sub(4 + 12 * 2 + 10 * 2);
  let mut y = 1;
  {
    let mut conns = connections.lock().unwrap();
    let mut values: Vec<_> = conns.values().filter(|v| v.stall_count < 10).collect();

    use std::borrow::Cow;
    values.sort_by_key(|v| &v.hostname);
    let mut stats: Vec<(_, PureStat)> = values
      .chunk_by(|a, b| a.hostname == b.hostname)
      .map(|stats| {
        let k = &stats[0].hostname;
        let n = stats.len();
        let st = stats.iter().fold(PureStat::default(), |acc, v| acc + v);

        let title = if n == 1 {
          let avail_width = target_width;
          let title = &k[..std::cmp::min(avail_width, k.len())];
          Cow::<str>::Borrowed(title)
        } else {
          let avail_width = target_width - 2 - int_width(n);
          let title = &k[..std::cmp::min(avail_width, k.len())];
          Cow::Owned(format!("{} x{}", title, n))
        };
        (title, st)
      })
      .collect();

    stats.sort_by_key(|x| std::cmp::Reverse(x.1.received));

    for (title, st) in stats {
      write!(buffer, "\x1b[{y};1H{:width$} {:9}/s↑ {:9}/s↓ {:9}↑ {:9}↓",
        title,
        Filesize(st.sent),
        Filesize(st.received),
        Filesize(st.total_sent),
        Filesize(st.total_received),
        width = target_width,
        y = y,
      ).unwrap();
      y += 1;
    }

    conns.retain(|_k, v| {
      if v.sent == 0 && v.received == 0 {
        v.stall_count += 1;
      } else {
        v.stall_count = 0;
      }
      v.sent = 0;
      v.received = 0;
      !v.last
    });
  }

  for y in y..=*last_y { // erase one more line
    write!(buffer, "\x1b[{y};1H\x1b[K").unwrap();
  }
  *last_y = y;
  let mut stdout = std::io::stdout();
  let _ = stdout.write_all(buffer); // WouldBlock if too many
  let _ = stdout.flush();
}

fn read_stdin() -> (bool, bool) {
  let mut buffer = [0u8; 16];
  let mut ctrl_c = false;
  let mut ctrl_l = false;
  let n = unsafe {
    libc::read(0, buffer.as_mut_ptr() as *mut _, buffer.len())
  };
  if n <= 0 {
    return (false, false);
  }
  for ch in &buffer[..n as usize] {
    if *ch == 3 { // ^C
      ctrl_c = true;
    } else if *ch == 12 { // ^L
      ctrl_l = true;
    }
  }

  (ctrl_c, ctrl_l)
}

fn int_width(n: usize) -> usize {
  (if n == 0 { 0 } else { n.ilog10() as usize }) + 1
}
