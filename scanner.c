#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#define BUFFER_SIZE 1024
#define MAX_PATH 256

/*
    Modify in place string to lowercase. 
*/
void strToLower(char *str) {
    int length = strlen(str);

    for (int i = 0; i < length; i++) {
        str[i] = tolower(str[i]);
    }

    return;
}

/*
    Check if path given exists and is a file.
    Return 1 if true, otherwise 0.
*/
int isFile(const char *path) {
    // stat stores info about a path
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

/*
    Check if path given exists and is a directory.
    Return 1 if true, otherwise 0.
*/
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

/*
    Print scan result to console.
*/
void printScan(char *sigFound, const char *path) {
    if (sigFound) {
        printf("\033[0;31m");       // red text
        printf("Malware signature: %s\ndetected in: %s!\n", sigFound, path);
        printf("\033[0m");          // reset color
    } 
    else {
        printf("\033[0;32m");       // green text
        printf("Found nothing in: %s\n", path);
        printf("\033[0m");          // reset color
    }

    return;
}

/* 
    Scans a single file.
    Return 1 if malware signature found, otherwise return 0.
*/
int sigScanF(char signatures[][100], int sigCount, char *path) {
    printf("Currently scanning: %s\n", path);

    // open and read file
    char buffer[BUFFER_SIZE];
    FILE *pFile = fopen(path, "r");

    // each call reads a string of BUFFER_SIZE char from pFile and put it into the buffer variable
    while(fgets(buffer, BUFFER_SIZE, pFile)) {
        strToLower(buffer);

        // check the buffer against each signature
        for (int i = 0; i < sigCount; i++) {
            if (strstr(buffer, signatures[i])) {
                printScan(signatures[i], path);
                fclose(pFile);
                return 1;
            }
        }
    }

    fclose(pFile);

    return 0;
}

/*
    Scans a directory.
    Return 1 if malware signature found, otherwise return 0.
*/ 
int sigScanDir(char signatures[][100], int sigCount, char *path) {
    int result = 0;

    // dirent represent a file in the directory
    struct dirent *directoryEntry;              
                
    // opens the directory
    DIR *directory = opendir(path);

    // for each entry in the directory
    while (directoryEntry = readdir(directory)) {
        // ignore . and .. and hidden files beginning with .
        if (directoryEntry->d_name[0] != '.') {

            char newPath[MAX_PATH+1] = "";                                              // +1 for null char
            sprintf(newPath, "%s/%s", path, directoryEntry->d_name);
            printf("Path detected: %s\n", newPath);

            // check if entry is a file or directory
            if (isFile(newPath)) {
                int r = sigScanF(signatures, sigCount, newPath);
                result = r > result ? r : result;
            }
            else if (isDir(newPath)) {
                int r = sigScanDir(signatures, sigCount, newPath);
                result = r > result ? r : result;
            }
        }
    }

    closedir(directory);
    
    return result;
}

int main(int argc, char *argv[]) {
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
    }

    if (argc == 1) {
        printf("No arguments was given\n");
    } 
    else if (argc > 1) {
        // path is at argv[1], check if path is a reg file or a dir

        if (isFile(argv[1])) {
            printf("Path given is a file\n");
        
            // scan the file for signatures
            if (sigScanF(signatures, numOfSignatures, argv[1]) == 0){
                printScan(NULL, argv[1]);
            }
        }
        else if (isDir(argv[1])) {
            printf("Path given is a directory\n");

            // scan directory
            if (sigScanDir(signatures, numOfSignatures, argv[1]) == 0) {
                printScan(NULL, argv[1]);
            };
        }
        else {
            printf("No such file or directory exists!\n");
        }
        
        printf("Scanning completed!\n");
    }

    return 0;
}