fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    {
        rdma::bindgen_mlx5dv();
        ucx::build_shim();
    }
}

#[cfg(all(feature = "rdma", target_os = "linux"))]
mod ucx {
    pub fn build_shim() {
        println!("cargo:rerun-if-changed=src/ucx_shim.c");
        let ucx = pkg_config::Config::new()
            .atleast_version("1.12")
            .probe("ucx")
            .expect("the `rdma` feature requires OpenUCX development headers (ucx.pc)");
        let mut build = cc::Build::new();
        build.file("src/ucx_shim.c");
        for path in ucx.include_paths {
            build.include(path);
        }
        build.flag_if_supported("-std=c11");
        build.compile("openlake_ucx_shim");
    }
}

#[cfg(all(feature = "rdma", target_os = "linux"))]
mod rdma {
    use std::{env, path::PathBuf};

    pub fn bindgen_mlx5dv() {
        println!("cargo:rustc-link-lib=mlx5");
        let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("mlx5dv_sys.rs");
        bindgen::Builder::default()
            .header_contents("wrapper.h", "#include <infiniband/mlx5dv.h>\n")
            .clang_arg("-D_GNU_SOURCE")
            .raw_line("use rdma_mummy_sys::*;")
            .allowlist_function("mlx5dv_.*")
            .allowlist_type    ("mlx5dv_.*")
            .allowlist_var     ("MLX5DV_.*")
            .blocklist_function("ibv_.*")
            .blocklist_type    ("ibv_.*")
            .blocklist_type    ("verbs_.*")
            .blocklist_type    ("__be.*")
            // mlx5dv_flow_* references ibv_flow_attr_type / ibv_flow_action_*
            // as types, but rdma-mummy-sys emits those as modules. We do not
            // use flow steering on DC, so blocklist the whole flow subsystem.
            .blocklist_type    ("mlx5dv_flow.*")
            .blocklist_function("mlx5dv_create_flow.*")
            .blocklist_function("mlx5dv_destroy_flow.*")
            .blocklist_function("mlx5dv_dr_.*")
            .blocklist_function("mlx5dv_flow.*")
            .blocklist_type    ("mlx5dv_context_attr")
            .blocklist_function("mlx5dv_open_device")
            .layout_tests(false)
            .derive_default(true)
            .generate().expect("bindgen mlx5dv.h")
            .write_to_file(&out).expect("write mlx5dv_sys.rs");
    }
}
