use clap::{Parser, Subcommand};
use kube::CustomResourceExt;

mod controller;
mod crds;

#[derive(Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the controller. This is the default command if no subcommand is specified.
    Run {},

    /// Generate the CRDs.
    Crds {},
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let reconcile_interval = std::time::Duration::from_secs(30);
    match args.command {
        None | Some(Command::Run {}) => {
            crate::controller::run(reconcile_interval).await;
        }
        Some(Command::Crds {}) => {
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
