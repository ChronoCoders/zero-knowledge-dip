use anyhow::Result;
use colored::Colorize;

pub async fn run() -> Result<()> {
    println!("{}", "🧪 Running full system test".bold().cyan());
    println!();

    let random_id = format!("test_sub_flow_{}", rand::random::<u32>());
    crate::commands::assign::run(random_id).await?;

    println!();
    println!("{}", "✅ All tests passed!".bold().green());

    Ok(())
}