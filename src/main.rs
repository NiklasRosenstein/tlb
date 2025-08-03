use clap::{Parser, Subcommand};
use kube::CustomResourceExt;

mod controller;
mod crds;
mod internal;

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

    /// Internal commands.
    #[command(subcommand)]
    Internal(InternalCommand),
}

#[derive(Subcommand, Debug)]
enum InternalCommand {
    /// Netbird commands.
    #[command(subcommand)]
    Netbird(NetbirdCommand),
}

#[derive(Subcommand, Debug)]
enum NetbirdCommand {
    /// Run the Netbird sidecar for a service.
    Run {
        /// The name of the service to run the sidecar for.
        #[arg(long)]
        service_name: String,

        /// TCP ports to forward.
        #[arg(long)]
        tcp: Vec<u16>,

        /// UDP ports to forward.
        #[arg(long)]
        udp: Vec<u16>,
    },
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
        Some(Command::Internal(internal)) => match internal {
            InternalCommand::Netbird(netbird) => match netbird {
                NetbirdCommand::Run {
                    service_name,
                    tcp,
                    udp,
                } => crate::internal::netbird::run(service_name, &tcp, &udp)
                    .await
                    .unwrap(),
            },
        },
    }
}
