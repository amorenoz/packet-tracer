use anyhow::Result;

mod collector;
mod config;
mod core;
use collector::get_collectors;
use config::{Cli, SubCommand};

fn main() -> Result<()> {
    let mut cli = Cli::new()?;
    let mut collectors = get_collectors()?;
    collectors.register_cli(&mut cli)?;
    cli.parse()?;
    let subcommand = cli.get_subcommand();
    match subcommand.expect("no subcommand") {
        SubCommand::Collect(collect) => {
            println!("Collecting {:#?}", collect);
            collectors.init(&cli)?;
            collectors.start(&cli)?;
        }
    }
    Ok(())
}
