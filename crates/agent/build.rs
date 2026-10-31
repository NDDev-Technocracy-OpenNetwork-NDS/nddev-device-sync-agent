fn main() {
    println!("cargo:rerun-if-env-changed=NDS_GITHUB_WORKER_SHA256");
}
