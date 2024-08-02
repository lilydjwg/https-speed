use std::fmt;

const UNITS: [char; 4] = ['K', 'M', 'G', 'T'];

pub struct Filesize(pub usize);

impl fmt::Display for Filesize {
  fn fmt(&self, f: &mut fmt::Formatter<'_>)
    -> fmt::Result {

    let mut left = self.0 as f64;
    let mut unit = -1;

    while left > 1100. && unit < 3 {
      left /= 1024.;
      unit += 1;
    }
    if unit == -1 {
      f.write_fmt(format_args!(
        "{:width$} B", self.0,
        width = f.width().unwrap_or(2) - 2,
      ))
    } else {
      f.write_fmt(format_args!(
        "{:width$.1} {}B", left, UNITS[unit as usize],
        width = f.width().unwrap_or(3) - 3,
      ))
    }
  }
}
