use clap::{Parser, Subcommand};
use kube::CustomResourceExt;
use serde::Serialize;
use serde_yaml::Value;

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
                serialize_crd_without_empty_arrays(crate::crds::TunnelClass::crd())
            );
            print!(
                "---\n{}",
                serialize_crd_without_empty_arrays(crate::crds::ClusterTunnelClass::crd())
            )
        }
    }
}

fn serialize_crd_without_empty_arrays<T: Serialize>(crd: T) -> String {
    let mut value = serde_yaml::to_value(crd).unwrap();
    remove_empty_array_fields(&mut value);
    serde_yaml::to_string(&value).unwrap()
}

fn remove_empty_array_fields(value: &mut Value) {
    match value {
        Value::Mapping(mapping) => {
            for child in mapping.values_mut() {
                remove_empty_array_fields(child);
            }

            mapping.retain(|_, child| !matches!(child, Value::Sequence(seq) if seq.is_empty()));
        }
        Value::Sequence(sequence) => {
            for child in sequence {
                remove_empty_array_fields(child);
            }
        }
        _ => {}
    }
}
