use std::error::Error;
use std::io::prelude::*;
use std::fs::File;
use std::path::Path;
extern crate rsdparsa;

fn main() {
    let path = Path::new("sdp.txt");
    let display = path.display();

    let mut file = match File::open(&path) {
        Err(why) => panic!("Failed to open {}: {}",
                             display,
                             why.description()),
        Ok(file) => file
    };

    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("couldn't read {}: {}",
                           display,
                           why.description()),
        Ok(s) => s
    };

    rsdparsa::parse_sdp(&s, true);
}
