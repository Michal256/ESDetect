#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

using std::cout;
using std::endl;

int main() {
    while (true) {
        cout << "Hello World" << endl;

        const char* filename = "created_file.txt";

        // Create file
        std::ofstream outfile(filename);
        outfile << "Content inside the file." << endl;
        outfile.close();

        // Set permissions to 644 (rw-r--r--)
        if (chmod(filename, 0644) != 0) {
            perror("chmod");
        }

        sleep(5);
    }
    return 0;
}
