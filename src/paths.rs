use std::{
    env,
    path::{Path, PathBuf},
};

pub fn project_path(parts: &[&str]) -> PathBuf {
    let relative = parts.iter().collect::<PathBuf>();
    for base in runtime_bases() {
        let candidate = base.join(&relative);
        if candidate.exists() {
            return candidate;
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn runtime_bases() -> Vec<PathBuf> {
    let mut bases = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            push_unique(&mut bases, parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = env::current_dir() {
        push_unique(&mut bases, current_dir);
    }
    push_unique(&mut bases, PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    bases
}

fn push_unique(items: &mut Vec<PathBuf>, value: PathBuf) {
    if !items.iter().any(|item| item == &value) {
        items.push(value);
    }
}
