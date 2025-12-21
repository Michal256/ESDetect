// Compile: docker run --rm -v "$PWD":/src -w /src gcc:15.2.0 g++ -o test test.cpp
// Run with strace: strace -o strace_output.txt ./test

#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

using std::cout;
using std::endl;

int main() {
    cout << "Hello World" << endl;

    const char* filename = "created_file.txt";

    // Create file
    std::ofstream outfile(filename);
    outfile << "Content inside the file." << endl;
    outfile.close();

    // Set permissions to 644 (rw-r--r--)
    if (chmod(filename, 0644) != 0) {
        perror("chmod failed");
        return 1;
    }

    while(true) {
        sleep(1);
    }

    return 0;
}
