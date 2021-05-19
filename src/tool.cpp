//
//  tool.cpp
//  seal-dir
//
//  Created by Shreedhar Hegde on 18/05/21.
//

#include <iostream>
#include <filesystem>
#include <fstream>
#include "../lib/seal-dir.cpp"

namespace fs = std::filesystem;
using namespace std;

int main (int argc, const char * argv[]) {
    prep_gcrypt();
    
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <dir_path>" << endl;
        return 1;
    }
    
    try {
        fs::path thePath(argv[1]);
        fs::directory_entry entry(thePath);
        
        cout << "Creating merkle tree...";
        tree root(entry);
        cout
            << "done" << endl
            << "The hash of the given directory:" << endl
            << root.digest_meta.value << endl;
        
    }
    catch (fs::filesystem_error& event) {
        cerr << "\e[31mError:\e[39m " << event.code().message() << ": " << event.path1().string() << endl;
        return event.code().value();
    }
    catch (unsupported& event) {
        cerr << "\e[31mError:\e[39m " << event.what() << endl;
    }
    catch (failed_algo& event) {
        cerr << "\e[31mError:\e[39m " << event.what() << endl;
    }
    
    return 0;
}
