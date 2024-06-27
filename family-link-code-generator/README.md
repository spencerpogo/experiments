# family-link-code-generator

### Building instructions

#### C version

This version is a bit more faithful to [the original C++ implementation](https://source.chromium.org/chromium/chromium/src/+/main:chrome/browser/ash/child_accounts/parent_access_code/authenticator.cc;l=125;bpv=0;bpt=0) in terms of types but I doubt that matters

Sorry these aren't going to be very beginner-friendly

1. Install boringssl (or openssl) and add them to the include path (`-I`) and link path `-L`
2. Link against libcrypto and libssl: `-lcrypto -lssl`
   - put the link path and the link arguments at the very end, or you might link against system libraries by accident
     (see below)
3. compile `main.c`

Example command which (currently, as of 2024-06-27) works on nix (`nix-shell -p boringssl.dev`):

```sh
gcc -I/nix/store/jsk306bxijzsw6pklbzppq4gvrcr6p19-boringssl-unstable-2024-02-15-dev/include -g -Wall -Werror -o main main.c -L/nix/store/gwgpa8hvnbrdfcnq8jgxppr860ff1540-boringssl-unstable-2024-02-15/lib -lssl -lcrypto
```

Then:

```sh
./main '<shared secret>'
```

### Rust version

This version is a bit more cursed with the type stuff because I used `as` which can be unsafe in some cases, but it seems to be working so whatever

No explanation needed just build with cargo as normal:

```sh
cargo build
```

or run it directly:

```sh
cargo run -- '<shared secret>'
```
