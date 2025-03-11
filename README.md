# MPEG Transport Stream Parser

## Dependencies

 - Rustup: https://rustup.rs/
   - Unfortunately, while I cannot condone the way in which rustup is installed, it is the simplest (and recommended) way to get a rust toolchain installed
   - You should be fine to keep the default installation options, required ones will be overwritten below

## Build

Once you have rustup, you may run:
```bash
rustup default nightly # Installs the nightly toolchain,
rustup update # Ensures everything is installed
```

This should install everything you need to build. Then, assuming you have the repository checked out, from within the cloned repository, run:

```bash
cargo build --release # Builds an optimised version
```

## Running

You can run the program in several ways:
```bash
cat /path/to/stream.ts | /path/to/project/target/release/mpeg-ts-parser
# Or, if you prefer to not overly use cat :)
/path/to/project/target/release/mpeg-ts-parser < /path/to/stream.ts
```

