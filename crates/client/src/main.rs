mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zkdip")]
#[command(about = "Zero-Knowledge Dedicated IP Client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Assign a new Dedicated IP")]
    Assign {
        #[arg(short, long, default_value = "test_subscription_123")]
        subscription_id: String,
    },
    #[command(about = "Test full flow: blind signature → IP assignment")]
    Test,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Assign { subscription_id } => {
            commands::assign::run(subscription_id).await?;
        }
        Commands::Test => {
            commands::test::run().await?;
        }
    }

    Ok(())
}
