use anyhow::{bail, Result};
use log::error;
use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

mod cli;
mod collect;
mod core;
mod module;
mod process;
use cli::get_cli;
use collect::get_collectors;
use process::PostProcess;

// Re-export derive macros.
use retis_derive::*;

fn main() -> Result<()> {
    let mut cli = get_cli()?.build()?;

    let log_level = match cli.main_config.log_level.as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        x => bail!("Invalid log_level: {}", x),
    };
    TermLogger::init(
        log_level,
        Config::default(),
        TerminalMode::Stderr, // Use stderr so logs do not conflict w/ other output.
        ColorChoice::Auto,
    )?;

    let command = cli.get_subcommand_mut()?;
    match command.name() {
        "collect" => {
            let mut collectors = get_collectors()?;

            collectors.register_cli(command.dynamic_mut().unwrap())?;
            let config = cli.run()?;

            collectors.init(&config)?;
            collectors.start(&config)?;

            // Starts a loop.
            collectors.process(&config)?;
        }
        "process" => {
            let _pp = PostProcess::new(cli.run()?)?;
        }
        _ => {
            error!("not implemented");
        }
    }
    Ok(())
}
