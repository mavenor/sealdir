/**
 # The `seal-dir` library
 A tool to cryptographically seal the state of an entire directory
 
 © 2021 Shreedhar Hegde
 LICENSE: BSD 3-Clause
 
 */

#include "seal-dir.hpp"

namespace fs = std::filesystem;

// BEGIN definitions for digest

    // CONSTRUCTORS:
    // -------------

    digest::digest (std::string& message) {
        gcry_md_hd_t ctx;
        gcry_md_open(&ctx, SEAL_DIR_HASH_ALGO, 0);
        gcry_md_write(ctx, message.c_str(), message.size());

        unsigned char * _digest = std::move(gcry_md_read(ctx, SEAL_DIR_HASH_ALGO));
        for (unsigned long i = 0; i < SEAL_DIR_HASH_ALGO_SIZE; i++)
            value += std::to_string(static_cast<unsigned>(_digest[i]));

        numeric = std::stoi(value, NULL, 16);
        gcry_md_close(ctx);
    }

    // OPERATORS:
    // ----------

    digest& digest::operator+ (digest& other) {
        std::string _tmp = (this->value + other.value);
        return *(new digest(_tmp));
    }

    void digest::operator+= (digest& other) {
        gcry_md_hd_t ctx;
        gcry_md_open(&ctx, SEAL_DIR_HASH_ALGO, 0);
        gcry_md_write(ctx, this->value.c_str(), this->value.size());
        gcry_md_write(ctx, other.value.c_str(), other.value.size());
        unsigned char * _digest_sum = std::move(gcry_md_read(ctx, SEAL_DIR_HASH_ALGO));

        value.clear();
        for (unsigned long i = 0; i < SEAL_DIR_HASH_ALGO_SIZE; i++)
            value += std::to_string(static_cast<unsigned>(_digest_sum[i]));

        gcry_md_close(ctx);

        numeric = std::stoi(value, NULL, 16);

        return;
    }

    bool digest::operator== (digest& other) {
        return (value == other.value);
    }

    bool digest::operator!= (digest& other) {
        return (value != other.value);
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
        value.clear();
        unsigned char * tmp = std::move(gcry_md_read(ctx, SEAL_DIR_HASH_ALGO));
        for (unsigned long i = 0; i < SEAL_DIR_HASH_ALGO_SIZE; i++)
            value += std::to_string(static_cast<unsigned>(tmp[i]));
        numeric = std::stoi(value, NULL, 16);
        return;
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
        
        unsigned char * __digest_raw_cstr = std::move(gcry_md_read(ctx, SEAL_DIR_HASH_ALGO));
        for (unsigned long i = 0; i < SEAL_DIR_HASH_ALGO_SIZE; i++) {
            digest_raw.value += std::to_string(static_cast<unsigned>(__digest_raw_cstr[i]));
        }
        // TODO: change 👆 to use methods of digest
        
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
            switch (fs::file_type offender = entry->symlink_status().type()) {
                    
                case fs::file_type::regular:
                case fs::file_type::symlink:
                    children[i] = *(new leaf (entry->path()));
                    break;
                    
                case fs::file_type::directory:
                    children[i] = *(new tree (entry->path()));
                    break;
                    
                default:
                    throw unsupported(offender);
                    break;
            }
            
            // hash the childrens’ hashes
            gcry_md_write(ctx_raw, children[i].digest_raw.value.c_str(), children[i].digest_raw.value.size());
            gcry_md_write(ctx_meta, children[i].digest_meta.value.c_str(), children[i].digest_meta.value.size());
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
