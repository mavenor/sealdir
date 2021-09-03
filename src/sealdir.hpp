
/**
 The `sealdir` library
 A tool to cryptographically seal the state of an entire directory
 
 © 2021 Shreedhar Hegde
 LICENSE: BSD 3-Clause
 
 */
#ifndef SEAL_DIR
#define SEAL_DIR

#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

#include <ctime>
#include <cstdio>
#include <ctime>

#include <gcrypt.h>

// set default algo to SHA-256 (SHA v2, 32-char-long digest)
#ifndef SEAL_DIR_HASH_ALGO
#define SEAL_DIR_HASH_ALGO GCRY_MD_SHA256
#endif

/// (n.) The block size to use when reading from the filesystem.
#define SEAL_DIR_HASH_BLK_SIZE (4<<10) // 4 KiB

/// (n.) The minimum version of `libgcrypt' needed. As of now, this is just set to the earliest version with all major bugs patched.
#define NEED_LIBGCRYPT_VERSION "1.8.7"

#define SEAL_DIR_GET_HASH(READY_CTX, FILE, F_SIZE, BUFFER, UL_TMP_VAR) \
    for (UL_TMP_VAR = F_SIZE; \
         UL_TMP_VAR >= SEAL_DIR_HASH_ALGO_SIZE; \
         UL_TMP_VAR = (F_SIZE - FILE.tellg())) \
    { \
        FILE.read(BUFFER, SEAL_DIR_HASH_ALGO_SIZE); \
        gcry_md_write(READY_CTX, BUFFER, SEAL_DIR_HASH_ALGO_SIZE); \
    } \
    FILE.read(BUFFER, UL_TMP_VAR); \
    gcry_md_write(READY_CTX, BUFFER, UL_TMP_VAR);

const unsigned long SEAL_DIR_HASH_ALGO_SIZE = gcry_md_get_algo_dlen(SEAL_DIR_HASH_ALGO);

namespace fs = std::filesystem;

/* ------- BitMask Definitions ------- */
static const std::ios::openmode readOnly  = ( std::ios::in | std::ios::binary );
static const std::ios::openmode readWrite = ( std::ios::in | std::ios::out | std::ios::binary );

static const std::ios::iostate eof = std::ios::eofbit;
static const std::ios::iostate dirty = ( std::ios::failbit | std::ios::badbit );
/* ----- End BitMask Definitions ----- */

/* ----------- Exceptions ----------- */
class unsupported : public std::exception {
    std::string offender;
    
public:
    unsupported (std::filesystem::file_type theOffender);
    const char * what (void) const noexcept;
};

class failed_algo : public std::exception {
public:
    const char * what (void) const noexcept {
        return "The chosen algorithm is unavailable in the current setup!\n";
    }
};
/* --------- End Exceptions --------- */

/* --------- Data Structures / Types --------- */
/// A hash-digest object
struct digest {
    unsigned * numeric;
    
    digest (std::string&);
    digest (unsigned *, size_t length = SEAL_DIR_HASH_ALGO_SIZE);
    
    digest (void) = default;
    digest (const digest&) = default;
    digest (digest&&) noexcept = default;

    digest& operator= (const digest&) = default;
    digest& operator= (digest&&) noexcept = default;
    
    digest& operator+ (digest& other);
    void operator+= (digest& other);
    bool operator== (digest& other);
    bool operator!= (digest& other);
    bool operator> (digest& other);
    bool operator>= (digest& other);
    bool operator< (digest& other);
    bool operator<= (digest& other);
    
    void read (gcry_md_hd_t& ctx);
    std::string& print (void);
};

/// Any general node in the Merkle tree, bound to the corresponding filesystem object
class bound_hash_node : public fs::directory_entry {
    
protected:
    int nChildren;
    bound_hash_node * children;
    
    
public:
    digest digest_raw, digest_meta;
    
    // OPERATORS:
    // ----------
    bool operator== (bound_hash_node&);

    // CONSTRUCTORS:
    // -------------
    bound_hash_node (const fs::path&);
    bound_hash_node (const fs::directory_entry&);
    // default stuff
    bound_hash_node (void) = default;
    bound_hash_node (const bound_hash_node&) = default;
    bound_hash_node (bound_hash_node&&) noexcept = default;
    bound_hash_node& operator= (const bound_hash_node&) = default;
    bound_hash_node& operator= (bound_hash_node&&) noexcept = default;
};
/// A leaf node of the Merkle tree — bound to a file
class leaf : public bound_hash_node {
private:
    /// The file associated with a leaf
    std::fstream file;
    
public:
    leaf (const fs::path&);
    leaf (const fs::directory_entry&);
    // ? Do we even want a default constructor 👇?
    leaf (void) = default;
    leaf (const leaf&);
    leaf (leaf&&) noexcept;
};

/// An internal node of the Merkle tree — bound to a directroy
class tree : public bound_hash_node {
public:
    tree (const fs::path&);
    tree (const fs::directory_entry&);
};


struct raw_hash_node;
class binary_hash_tree;
/* ------- End Data Structures ------- */


/* ------ Function Definitions ------ */

/* ---- End Function Definitions ---- */

#endif /* seal_dir_hpp */
