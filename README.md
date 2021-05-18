# seal-dir
A C++ library and CLI tool 🔧 to seal a directory’s state 📦 📨.
<br>Makes it hard for somebody to tamper with a directory  *and* get away with it, sans leaving traces.

It’s been done before — directory [hash-trees](https://en.wikipedia.org/wiki/Merkle_tree) (also “*Merkle trees*” after their creator [Ralph C. Merkle](https://www.merkle.com))] are under the hood of **git 🎋⌥ itself**, modern cryptocurrency, the BitTorrent protocol 📥, and macOS [SSV](https://eclecticlight.co/2020/11/30/is-big-surs-system-volume-sealed). But this project aims at making available a **near-standalone library** (as well as an exemplifying frontend CLT) to allow for any other great ideas yet unimplemented to gain a head-start.

**`documentation coming soon`** (once the library gets big enough — if it gets big enough)

## Build Requirements
Relies on the [GnuPG](https://gnupg.org) project’s crypto library ([`libgcrypt`](https://gnupg.org/software/libgcrypt/index.html)) for all the hashing work.
Until the building process is automated by the authoring of Makefiles and such (which the author *does* eventually plan to do), you will need to **ensure your compiler and linker have access to `libgcrypt`’s headers and object-libraries. You can find out what flags to pass to your compiler by running `libgcrypt-config --cflags --libs`, once you have ensured that `libgcrypt` is installed.

**N.B.:** `libgcrypt` is distributed under the **[GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.txt)**, which has different terms and distribution-restrictions from the **BSD “3-Clause” license** used in the rest of this software.
