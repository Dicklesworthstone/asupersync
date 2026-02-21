use asupersync::process::Command;

async fn run_command() -> std::io::Result<()> {
    let output = Command::new("echo")
        .arg("hello")
        .output()
        .await?;
    Ok(())
}
