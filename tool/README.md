# Updating to new libseccomp version

This tool upgrades libseccomp-sys to a new version of the libseccomp library using `bindgen`.
You can generate low-level bindings of the the latest version easily and quickly.
The tool will be used by developers of this crate.

## How to upgrade

1. Build and install the latest liseccomp library from the source
   ```sh
   $ wget https://github.com/seccomp/libseccomp/releases/download/v2.5.1/libseccomp-2.5.1.tar.gz
   $ tar xvf libseccomp-2.5.1.tar.gz
   $ cd libseccomp-2.5.1
   $ ./configure
   $ make
   $ sudo make install   
   ```

2. Generate low-level API automatically
   The tool requires `seccomp.h`.
   Run the following step if `seccomp.h` is under `/usr/local/include`.
   The new version of low-level bindings is created as libseccomp-sys/src/libseccomp_bindings.rs`.

   ```sh
   // change this directory
   $ cd tool
   // Run the tool without command line arguments
   $ cargo run
   ``` 

   If `seccomp.h` is not under `/usr/local/include`,
   you need to set the `seccomp.h` path from the commmand line.

   ```sh
   $ cargo run "<path>/include"
   ```
