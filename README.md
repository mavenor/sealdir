# seal-dir
A C++ library and CLI tool 🔧 to seal a directory’s state 📦 📨. In essence, gets the **hash of a directory**.

While that technically doesn’t mean one specific thing (capable of being interpreted and/or implemented in different ways), here it means recursively hashing its contents using a **tree structure**. Including the metadata of each dir-tree node as well, this “*stamp*” hash that is thus calculated *should* make it very hard for a directory to be tampered with secretly.

It’s been done before — [hash-trees](https://en.wikipedia.org/wiki/Merkle_tree) (also “*Merkle trees*” after their creator [Ralph C. Merkle](https://www.merkle.com)) of directories are used in the BitTorrent protocol 📥, macOS [SSV](https://eclecticlight.co/2020/11/30/is-big-surs-system-volume-sealed), and **git 🎋⌥ itself**.

But this project aims at making a **near-standalone library** (as well as an exemplifying frontend CLT) available, for any other great ideas yet unimplemented to gain a head-start.

**`documentation coming soon`** (once the library gets big enough — if it gets big enough)

## Build Requirements
Relies on the [GnuPG](https://gnupg.org) project’s crypto library ([`libgcrypt`](https://gnupg.org/software/libgcrypt/index.html)) for all the hashing work.
1. Ensure that `libgcrypt` (≥ `v1.8.7`) is installed on your system. If you’re on **linux**, you can probably **skip this step**. For other platforms, the easiest way is often to get GnuPG itself. There are several binaries suggested by GnuPG [here](https://gnupg.org/download/index.html#binary).
2. Ensure your compiler and linker have access to `libgcrypt`’s headers and object-libraries. You can find out what flags to pass to your compiler by running `libgcrypt-config --cflags --libs`, once you have ensured that `libgcrypt` is installed.
3. Build!
    - macOS (requires Xcode CLT <small>or a separate installation of `clang` or `gcc`</small>):
        ```sh
        clang++ -dylib -std=gnu++17 ./src/* -o libsealdir.dylib
        ```
    - Linux:
        ```sh
        g++ -flinker-output=dyn -std=gnu++17 ./src/* -o libsealdir.so
        ```

**N.B.:** `libgcrypt` is distributed under the **[GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.txt)**, which has different terms and distribution-restrictions from the **BSD “3-Clause” license** used in the rest of this software.
