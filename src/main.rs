use clap::{Parser, Subcommand};
use kube::CustomResourceExt;

mod controller;
mod crds;

#[derive(Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the controller.
    Run {},

    /// Generate the CRDs.
    Crds {},
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    match args.command {
        Command::Run {} => {
            crate::controller::run().await;
        }
        Command::Crds {} => {
            print!(
                "---\n{}",
                serde_yaml::to_string(&crate::crds::TunnelClass::crd()).unwrap()
            );
            print!(
                "---\n{}",
                serde_yaml::to_string(&crate::crds::ClusterTunnelClass::crd()).unwrap()
            )
        }
    }
}
