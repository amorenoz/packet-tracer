#![allow(dead_code)] // FIXME
use std::{fs, path::PathBuf};

use anyhow::{anyhow, bail, Result};
use rhai::{Engine, AST};

/// Rai implementation of a Profile
pub(crate) struct Profile {
    engine: Engine,
    ast: AST,
}

impl Profile {
    pub fn load(path: PathBuf) -> Result<Profile> {
        let path = path.canonicalize()?;
        if !fs::metadata(&path)?.is_file() {
            bail!("Profile not found: {:?}", path)
        }

        let engine = Engine::new();
        let ast = engine
            .compile_file(path)
            .map_err(|e| anyhow!("Failed to compile profile {:?}", e))?;
        Ok(Profile { engine, ast })
        //FIXME: Run profile validation.
    }

    pub fn has_collect(&self) -> Result<bool> {
        Ok(self
            .ast
            .iter_functions()
            .find(|s| s.name == "collect")
            .is_some())
    }

    pub fn has_process(&self) -> Result<bool> {
        Ok(self
            .ast
            .iter_functions()
            .find(|s| s.name == "process")
            .is_some())
    }
}
