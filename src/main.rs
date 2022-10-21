use anyhow::Result;

mod collector;
mod config;
mod core;
use collector::get_collectors;
use config::Cli;

fn main() -> Result<()> {
    let _ = Cli::new();
    let mut collectors = get_collectors()?;
    collectors.init()?;
    collectors.start()?;
    Ok(())
}
