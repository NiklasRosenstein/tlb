use clap::{Parser, Subcommand};
use kube::CustomResourceExt;

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

fn main() {
    let args = Args::parse();
    match args.command {
        Command::Run {} => {
            // Placeholder for the run command logic
            println!("Running the controller...");
        }
        Command::Crds {} => {
            print!("---\n{}", serde_yaml::to_string(&crate::crds::TunnelClass::crd()).unwrap());
            print!("---\n{}", serde_yaml::to_string(&crate::crds::ClusterTunnelClass::crd()).unwrap())
        }
    }
}
