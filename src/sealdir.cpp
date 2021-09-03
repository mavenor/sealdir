/**
 The `sealdir` library
 A tool to cryptographically seal the state of an entire directory
 
 © 2021 Shreedhar Hegde
 LICENSE: BSD 3-Clause
 
 */

#include "sealdir.hpp"

/**
 Library initialisation (style depends on compiler).
 Dependancy `libgcrypt` needs to be initialised (see https://gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html)
 */
#ifdef __GNUC__ // for all GCC-compatible compilers...
// Prototype declaration for `prep_gcrypt()' as this library's constructor
void __attribute__((constructor)) prep_gcrypt();

#elif defined (_WIN32) // with MSVC, use DllMain
// MSVC automatically gets DllMain() to be called in the
// ... heirarchy of initialisation (see https://docs.microsoft.com/en-us/cpp/build/run-time-library-behavior#initialize-a-dll)
// Substitute (regular) prototype delcaration instead of __attribute__((constructor))
void prep_gcrypt(void);

// DllMain from template to prepare libgcyrpt
extern "C" BOOL WINAPI DllMain(
    HINSTANCE const instance,
    DWORD     const reason,
    LPVOID    const reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH: // for new processes only
        prep_gcrypt();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

#else

#error \
Could not set up libgcrypt for automatic initialisation. Is your build system/compiler \
somewhat unconventional? (If it isn't please file a bug report on GitHub) \
For now, configure `src/sealdir.cpp' to the needs of your environment, such that it calls `prep_gcrypt()' \
immediately on startup.

#endif

/**
 (v.) prep_gcrypt:
 Initialise `libgcrypt` with unsecured memory.
 */
void prep_gcrypt (void) {
    if (!gcry_check_version(NEED_LIBGCRYPT_VERSION)) {
        std::cerr << "libgcrypt is too old (need " << NEED_LIBGCRYPT_VERSION << ", found " << gcry_check_version(NULL) << ")\n";
        exit(2);
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}


namespace fs = std::filesystem;

// BEGIN definitions for digest

    // CONSTRUCTORS:
    // -------------

    digest::digest (std::string& message) {
        gcry_md_hd_t ctx;
        gcry_md_open(&ctx, SEAL_DIR_HASH_ALGO, 0);
        gcry_md_write(ctx, message.c_str(), message.size());
        
        read(ctx);
        
        gcry_md_close(ctx);
    }

    digest::digest (unsigned * data, size_t length) {
        gcry_md_hd_t ctx;
        gcry_md_open(&ctx, SEAL_DIR_HASH_ALGO, 0);
        gcry_md_write(ctx, &data, length);
        
        read(ctx);
        
        gcry_md_close(ctx);
    }

    // OPERATORS:
    // ----------

    digest& digest::operator+ (digest& other) {
        unsigned * _total = new unsigned [SEAL_DIR_HASH_ALGO_SIZE*2];
        for (unsigned long i = 0; i < SEAL_DIR_HASH_ALGO_SIZE; i++) {
            _total[i]                           = this->numeric[i];
            _total[i + SEAL_DIR_HASH_ALGO_SIZE] = other.numeric[i];
        }
        return *(new digest(_total, SEAL_DIR_HASH_ALGO_SIZE*2));
    }

    void digest::operator+= (digest& other) {
        gcry_md_hd_t ctx;
        gcry_md_open(&ctx, SEAL_DIR_HASH_ALGO, 0);
        gcry_md_write(ctx, this->numeric, SEAL_DIR_HASH_ALGO_SIZE);
        gcry_md_write(ctx, other.numeric, SEAL_DIR_HASH_ALGO_SIZE);
        
        read(ctx);
        
        gcry_md_close(ctx);

        return;
    }

    bool digest::operator== (digest& other) {
        return (numeric == other.numeric);
    }

    bool digest::operator!= (digest& other) {
        return (numeric != other.numeric);
    }

    bool digest::operator> (digest& other) {
        return (numeric > other.numeric);
    }

    bool digest::operator>= (digest& other) {
        return (numeric >= other.numeric);
    }

    bool digest::operator< (digest& other) {
        return (numeric < other.numeric);
    }

    bool digest::operator<= (digest& other) {
        return (numeric <= other.numeric);
    }

    void digest::read (gcry_md_hd_t& ctx) {
        numeric = new unsigned [SEAL_DIR_HASH_ALGO_SIZE];
        unsigned char * _hash = gcry_md_read(ctx, SEAL_DIR_HASH_ALGO);
        
        for (unsigned long i = 0; i < SEAL_DIR_HASH_ALGO_SIZE; i++)
            numeric[i] = std::move(_hash[i]);
        
        return;
    }

    std::string& digest::print (void) {
        std::stringstream _hex_value;
        for (unsigned long i = 0; i < SEAL_DIR_HASH_ALGO_SIZE; i++)
            _hex_value << std::hex << std::setw(2) << std::setfill('0') << numeric[i];
        
        std::string& output = *(new std::string);
        _hex_value >> output;
        return output;
    }

// END definitions for digest


// BEGIN definitions for bound_hash_node
    
    // OPERATORS:
    // ----------
    bool bound_hash_node::operator== (bound_hash_node& other) {
        if (this->digest_raw == other.digest_raw)
            return true;
        else
            return false;
    }
    
    // CONSTRUCTORS:
    // -------------
    bound_hash_node::bound_hash_node (const fs::path& thePath) : directory_entry(thePath) {
        nChildren = 0;
        children = nullptr;
    }
    
    bound_hash_node::bound_hash_node (const fs::directory_entry& theEntry) : bound_hash_node(theEntry.path()) {}
    
// END definitions for bound_hash_node

// BEGIN definitions for leaf

    leaf::leaf (const fs::path& thePath) : bound_hash_node(thePath) {
        file.open(thePath, readOnly);
        file.exceptions(dirty);
        if (gcry_md_test_algo(SEAL_DIR_HASH_ALGO) > 0)
            throw failed_algo();
        
        unsigned long file_size = fs::file_size(thePath);
        char * buffer = new char[SEAL_DIR_HASH_BLK_SIZE];
        
        gcry_md_hd_t ctx;
        gcry_md_open(&ctx, SEAL_DIR_HASH_ALGO, 0);
        
//        SEAL_DIR_GET_HASH(ctx, file, file_size, buffer, file_remain)
        unsigned long file_remain;
        for (file_remain = file_size;
             file_remain >= SEAL_DIR_HASH_ALGO_SIZE;
             file_remain = (file_size - file.tellg()))
        {
            file.read(buffer, SEAL_DIR_HASH_ALGO_SIZE);
            gcry_md_write(ctx, buffer, SEAL_DIR_HASH_ALGO_SIZE);
        }
        file.read(buffer, file_remain);
        gcry_md_write(ctx, buffer, file_remain);
        
        digest_raw.read(ctx);
        
        // digest with meta
        gcry_md_reset(ctx);
        gcry_md_enable(ctx, SEAL_DIR_HASH_ALGO);
        file.seekg(0, std::ios::beg);
        for (file_remain = file_size;
             file_remain >= SEAL_DIR_HASH_ALGO_SIZE;
             file_remain = (file_size - file.tellg()))
        {
            file.read(buffer, SEAL_DIR_HASH_ALGO_SIZE);
            gcry_md_write(ctx, buffer, SEAL_DIR_HASH_ALGO_SIZE);
        }
        file.read(buffer, file_remain);
        gcry_md_write(ctx, buffer, file_remain);
//        SEAL_DIR_GET_HASH(ctx, file, file_size, buffer, file_remain)
        
        /* meta */
        std::string
        __fstr_size = std::to_string(file_size),
        __fstr_name = thePath.filename().string(),
        __fstr_perm = std::to_string(static_cast<int>(this->symlink_status().permissions()));
        // TODO: include time
        // something like this:
        // __fstr_time = std::asctime(std::gmtime(std::chrono::system_clock::to_time_t(static_cast<std::chrono::system_clock>(this->last_write_time()))));
        
        gcry_md_write(ctx, __fstr_name.c_str(), __fstr_name.length());
        gcry_md_write(ctx, __fstr_perm.c_str(), __fstr_perm.length());
        gcry_md_write(ctx, __fstr_size.c_str(), __fstr_size.length());
//        gcry_md_write(ctx, __fstr_time.c_str(), __fstr_time.length());
        
        digest_meta.read(ctx);
        /* end meta */
        
        gcry_md_close(ctx);
        file.close();
        delete [] buffer;
    }
    
    leaf::leaf (const fs::directory_entry& theEntry) : leaf(theEntry.path()) {}
    leaf::leaf (const leaf& other) : bound_hash_node(other) {};
    leaf::leaf (leaf&& other) noexcept : bound_hash_node(other) {};

// END definitions for leaf

// BEGIN definitions for tree

    tree::tree (const fs::path& thePath) : bound_hash_node(thePath) {
        gcry_md_hd_t ctx_raw;
        gcry_md_open(&ctx_raw, SEAL_DIR_HASH_ALGO, 0);
        
        gcry_md_hd_t ctx_meta;
        gcry_md_open(&ctx_meta, SEAL_DIR_HASH_ALGO, 0);
        
        for (directory_entry child : fs::directory_iterator(thePath))
            nChildren++;
        
        children = new bound_hash_node [nChildren];
        fs::directory_iterator entry(thePath);
        for (int i = 0; entry != fs::end(entry); entry++) {
            switch (fs::file_type type = entry->symlink_status().type()) {
                case fs::file_type::regular:
                case fs::file_type::symlink:
                    children[i] = *(new leaf (entry->path()));
                    break;
                    
                case fs::file_type::directory:
                    children[i] = *(new tree (entry->path()));
                    break;
                    
                default:
                    throw unsupported(type);
                    break;
            }
            
            // hash the childrens’ hashes
            gcry_md_write(ctx_raw, children[i].digest_raw.numeric, SEAL_DIR_HASH_ALGO_SIZE);
            gcry_md_write(ctx_meta, children[i].digest_meta.numeric, SEAL_DIR_HASH_ALGO_SIZE);
        }
        
        digest_raw.read(ctx_raw);
        digest_meta.read(ctx_meta);
    }
    
    tree::tree (const fs::directory_entry& theEntry) : tree(theEntry.path()) {}

// END definitions for tree

/* EXCEPTION `UNSUPPORTED' */
unsupported::unsupported (std::filesystem::file_type theOffender) {
    switch (theOffender) {
        case std::filesystem::file_type::block:
            offender = "block special";
            break;
        case std::filesystem::file_type::character:
            offender = "character special";
            break;
        case std::filesystem::file_type::fifo:
            offender = "FIFO (pipe)";
            break;
        case std::filesystem::file_type::socket:
            offender = "socket";
            break;
        default:
            offender = "unrecognisable";
            break;
    }
}

const char * unsupported::what (void) const noexcept {
    return std::move(("A(n) " + offender + " file was found in the given directory!").c_str());
}

struct raw_hash_node {
    digest& hash;
    raw_hash_node * left, * right;
    bound_hash_node * data;

    raw_hash_node (raw_hash_node& theLeft, raw_hash_node& theRight) : hash(*(new digest)) {
        left = &theLeft;
        right = &theRight;
        this->hash = left->hash + right->hash;
    }
    
    raw_hash_node (bound_hash_node& data) : hash(data.digest_meta) {
        left = NULL;
        right = NULL;
        this->data = &data;
    }
    
    raw_hash_node (void) = delete;
};
