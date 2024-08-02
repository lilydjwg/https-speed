use tls_parser as tls;

pub fn parse_sni(payload: &[u8]) -> Option<&str> {
  let (_, r) = tls::parse_tls_raw_record(payload).ok()?;
  let (_, msg_list) = tls::parse_tls_record_with_header(r.data, &r.hdr).ok()?;
  if let tls::TlsMessage::Handshake(handshake) = &msg_list[0] &&
    let tls::TlsMessageHandshake::ClientHello(hello) = handshake
  {
    let ext = hello.ext?;
    let (_, exts) = tls::parse_tls_extensions(ext).ok()?;
    for ext in exts {
      if let tls::TlsExtension::SNI(snis) = ext {
        for (typ, data) in snis {
          if typ == tls::SNIType::HostName {
            return std::str::from_utf8(data).ok();
          }
        }
      }
    }
  }

  None
}
