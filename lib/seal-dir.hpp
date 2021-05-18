
/**
 # The `seal-dir` library
 A tool to cryptographically seal the state of an entire directory
 
 © 2021 Shreedhar Hegde
 LICENSE: BSD 3-Clause
 
 */
#ifndef SEAL_DIR
#define SEAL_DIR

#include <iostream>
#include <filesystem>
#include <fstream>
#include <chrono>

#include <ctime>
#include <cstdio>
#include <ctime>

#include <gcrypt.h>

// set default algo to SHA-256 (SHA v2, 32-char-long digest)
#ifndef SEAL_DIR_HASH_ALGO
#define SEAL_DIR_HASH_ALGO GCRY_MD_SHA256
#endif

#define SEAL_DIR_HASH_BLK_SIZE (4<<10) // 4 KiB
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
    inline unsupported (std::filesystem::file_type theOffender);
    inline const char * what (void) const noexcept;
};

class failed_algo : public std::exception {
public:
    const char * what (void) const noexcept {
        return "The chosen algorithm is unavailable in the current setup!\n";
    }
};
/* --------- End Exceptions --------- */

/* --------- Data Structures / Types --------- */
class bound_hash_node;
class leaf; // (FILE)
class tree; // (DIR)
struct digest {
    std::string value;
    int numeric;
    
    inline digest (std::string&);
    
    digest (void);
    digest (const digest&) = default;
    digest (digest&&) noexcept = default;

    digest& operator= (const digest&) = default;
    digest& operator= (digest&&) noexcept = default;
    
    inline digest& operator+ (digest& other);
    inline void operator+= (digest& other);
    inline bool operator== (digest& other);
    inline bool operator!= (digest& other);
    inline bool operator> (digest& other);
    inline bool operator>= (digest& other);
    inline bool operator< (digest& other);
    inline bool operator<= (digest& other);
    
    inline void read (gcry_md_hd_t& ctx);
    inline void read (unsigned char * c_str, unsigned long length);
};
struct raw_hash_node;
class binary_hash_tree;
/* ------- End Data Structures ------- */


/* ------ Function Definitions ------ */
/**
 Prep the `gcrypt` library with unsecured memory
 */
void prep_gcrypt (void) {
    if (!gcry_check_version (NEED_LIBGCRYPT_VERSION)) {
        std::cerr << "libgcrypt is too old (need %s, have %s)\n" << NEED_LIBGCRYPT_VERSION << gcry_check_version (NULL);
        exit(2);
      }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}
/* ---- End Function Definitions ---- */

#endif /* seal_dir_hpp */
