fn main() {
    println!("cargo:rerun-if-env-changed=NDS_GDS_WORKER_SHA256");
}
