use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{process::Command, time::timeout};

/// Run a child with a deadline. Cancellation kills the child rather than detaching it.
pub async fn run(program: &str, args: &[&str], seconds: u64) -> Result<()> {
    eprintln!("+ {program} {}", args.join(" "));
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("start {program}"))?;
    let status = match timeout(Duration::from_secs(seconds), child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            child.kill().await.context("kill timed-out command")?;
            anyhow::bail!("{program} exceeded {seconds}s");
        }
    };
    ensure!(status.success(), "{program} exited with {status}");
    Ok(())
}

pub async fn capture(program: &str, args: &[&str]) -> Result<String> {
    let output = timeout(
        Duration::from_secs(30),
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .with_context(|| format!("{program} exceeded 30s"))??;
    ensure!(
        output.status.success(),
        "{program}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reports_failed_commands_and_deadlines() {
        assert!(run("false", &[], 5).await.is_err());
        let started = tokio::time::Instant::now();
        let error = run("sleep", &["30"], 1).await.unwrap_err();
        assert!(error.to_string().contains("exceeded 1s"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
