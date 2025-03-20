#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#define BUFFER_SIZE 1024

void strToLower(char *str) {
    // modify str in place
    int length = strlen(str);

    for (int i = 0; i < length; i++) {
        str[i] = tolower(str[i]);
    }

    return;
}

int isFile(const char *path) {
    struct stat stats;
    int isPathExist;

    // fill stats with data about the path given
    // stat() returns 0 if successful
    isPathExist = stat(path, &stats);

    // S_ISREG returns non-zero if path is a regular file
    if (isPathExist == 0 && S_ISREG(stats.st_mode)) {
        return 1;
    }

    return 0;
}

int isDir(const char *path) {
    struct stat stats;
    int isPathExist;

    isPathExist = stat(path, &stats);

    // S_ISDIR returns non-zero if path is a dir
    if (isPathExist == 0 && S_ISDIR(stats.st_mode)) {
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {

    if (argc == 1) {
        printf("No arguments was given\n");
    } 
    else if (argc > 1) {
        // path is at argc[1], check if path is a reg file or a dir
        if (isFile(argv[1])) {
            printf("Path given is a file\n");
        }

        if (isDir(argv[1])) {
            printf("Path given is a directory\n");
        }


        // define malware signatures
        char signatures[][100] = {
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            "malicious_code",
            "SUSPICIOUSFUNCTIONCALL",
            "ransomware.startup",
        };
    
        int numOfSignatures = sizeof(signatures) / sizeof(signatures[0]);
    
        // change signatures to lowercase
        for (int i = 0; i < numOfSignatures; i++) {
            strToLower(signatures[i]);
            //printf("%s\n", signatures[i]);
        }
    
        // open and read a file
        char buffer[BUFFER_SIZE];
        FILE *pFile = fopen(argv[1], "r");
    
        // scan for signatures
        if (pFile != NULL) {
            // each call reads a string of BUFFER_SIZE char from pFile and put it into the buffer variable
            while(fgets(buffer, BUFFER_SIZE, pFile)) {
                strToLower(buffer);
                printf("%s", buffer);
    
                for (int i = 0; i < numOfSignatures; i++) {
                    if (strstr(buffer, signatures[i])) {
                        printf("Malicious signature: %s, is detected in file!!\n", signatures[i]);
                        
                        fclose(pFile);
                        return 0;
                    }
                }
            }              
        }
        else {
            printf("File does not exist!\n");
            return 1;
        }
    
        // close file
        fclose(pFile);
    }

    return 0;
}