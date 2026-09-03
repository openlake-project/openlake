fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "cuda")]
    cuda::build_codec();
}

// Compiles cuda/src/kv_compression.cu (the GPU codec used by the connector's
// optional low-bandwidth KV transfer path) into a static lib and links it
// plus the CUDA runtime into the `openlake_client` extension. Mirrors
// openlake_io/build.rs's `cc::Build` pattern for ucx_shim.c.
#[cfg(feature = "cuda")]
mod cuda {
    use std::env;
    use std::path::PathBuf;

    pub fn build_codec() {
        println!("cargo:rerun-if-changed=cuda/src/kv_compression.cu");
        println!("cargo:rerun-if-changed=cuda/include/openlake/kv_compression.h");

        let mut build = cc::Build::new();
        build
            .cuda(true)
            .flag("-std=c++17")
            .flag("--expt-relaxed-constexpr")
            .include("cuda/include")
            .file("cuda/src/kv_compression.cu");

        let archs = env::var("OPENLAKE_CUDA_ARCHS").unwrap_or_else(|_| "80,89,90".to_string());
        for arch in archs.split(',').map(str::trim).filter(|a| !a.is_empty()) {
            build.flag(format!("-gencode=arch=compute_{arch},code=sm_{arch}"));
        }

        build.compile("openlake_kv_cuda_codec");

        if let Some(lib_dir) = cuda_runtime_lib_dir() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
        }
        println!("cargo:rustc-link-lib=dylib=cudart");
    }

    /// Best-effort discovery of the CUDA runtime's lib dir, so `cudart` links
    /// even when it is not already on the default linker search path.
    fn cuda_runtime_lib_dir() -> Option<PathBuf> {
        let home = env::var_os("CUDA_HOME")
            .or_else(|| env::var_os("CUDA_PATH"))
            .map(PathBuf::from)
            .or_else(|| {
                which_nvcc().and_then(|nvcc| {
                    // .../<cuda-home>/bin/nvcc -> <cuda-home>
                    nvcc.parent()
                        .and_then(|bin| bin.parent())
                        .map(PathBuf::from)
                })
            })?;
        for candidate in ["lib64", "lib/x64", "lib"] {
            let path = home.join(candidate);
            if path.is_dir() {
                return Some(path);
            }
        }
        None
    }

    fn which_nvcc() -> Option<PathBuf> {
        let path = env::var_os("PATH")?;
        env::split_paths(&path)
            .map(|dir| dir.join("nvcc"))
            .find(|candidate| candidate.is_file())
    }
}
