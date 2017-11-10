extern crate goblin;
extern crate metagoblin;
extern crate env_logger;

use std::path::Path;
use std::fs::File;
use std::io::Read;
use std::env;
use goblin::error;

fn run () -> error::Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let mut fd = File::open(path)?;
            let buffer = { let mut v = Vec::new(); fd.read_to_end(&mut v).unwrap(); v};
            let res = goblin::Object::parse(&buffer)?;
            let analysis = metagoblin::Analysis::new(&res);
            //println!("{:#?}", analysis);
            for (range, data) in analysis.franges.iter() {
                print!("{:#x}..{:#x}({}) -> ", range.min, range.max, range.len() - 1);
                print!("{:?} - {:?}", data.tag, data.name().unwrap_or("None"));
                if let &Some(ref segment) = &data.memory {
                    print!(" : {}", segment.permissions);
                }
                println!("");
            }
        }
    }
    Ok(())
}

pub fn main () {
    env_logger::init().unwrap();
    match run() {
        Ok(()) => (),
        Err(err) => println!("{:#}", err)
    }
}
