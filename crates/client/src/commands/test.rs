use anyhow::Result;
use colored::Colorize;

pub async fn run() -> Result<()> {
    println!("{}", "🧪 Running full system test".bold().cyan());
    println!();

    crate::commands::assign::run("test_sub_flow_123".to_string()).await?;

    println!();
    println!("{}", "✅ All tests passed!".bold().green());

    Ok(())
}
