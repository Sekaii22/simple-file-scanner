#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

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
void printScan(char *sigFound, const char *path, const int noOfThreats, const char mode) {
    if (mode == 's') {
        printf("Currently scanning: %s\n", path);
    }
    else if (mode == 'm') {
        printf("\033[0;31m");       // red text
        printf("Malware signature: %s\nDetected in: %s\n", sigFound, path);
        printf("\033[0m");          // reset color
    }
    else if (mode == 'c') {
        printf("Scanning completed, %d threats were found.\n", noOfThreats);
    }
    else {
        printf("No corresponding mode!");
    }
}

/*
    Logs result to a file.
*/
void logScan(char *sigFound, const char *path, const int noOfThreats, const char mode) {
    // mode: (s - currently scanning) (m - malware detected) (c - completed) (t - time)
    FILE *pWriteFile = fopen("scan.log", "a");
    
    if (mode == 's') {
        fprintf(pWriteFile, "Currently scanning: %s\n", path);
    }
    else if (mode == 'm') {
        fprintf(pWriteFile, "Malware signature: %s\nDetected in: %s!\n", sigFound, path);
    }
    else if (mode == 'c') {
        fprintf(pWriteFile, "Scanning completed, %d threats were found.\n", noOfThreats);
    }
    else if (mode == 't') {
        // logs current date and time
        struct tm *pCalenderTime;
        time_t timeInSec = time(NULL);

        // fill calender time structure info using timeInSec
        pCalenderTime = localtime(&timeInSec);

        // write the date in a certain format
        char timeBuffer[70];
        strftime(timeBuffer, sizeof timeBuffer, "%a %d/%m/%y %T", pCalenderTime);
        fprintf(pWriteFile, "\n%s\n", timeBuffer);
    }
    else {
        printf("No corresponding mode!");
    }

    fclose(pWriteFile);
}

/* 
    Scans a single file.
    Return 1 if malware signature found, otherwise return 0.
*/
int sigScanF(char signatures[][100], int sigCount, char *path) {
    printScan(NULL, path, 0, 's');
    logScan(NULL, path, 0, 's');

    // open and read file
    char buffer[BUFFER_SIZE];
    FILE *pFile = fopen(path, "r");

    // each call reads a string of BUFFER_SIZE char from pFile and put it into the buffer variable
    while(fgets(buffer, BUFFER_SIZE, pFile)) {
        strToLower(buffer);

        // check the buffer against each signature
        for (int i = 0; i < sigCount; i++) {
            if (strstr(buffer, signatures[i])) {
                printScan(signatures[i], path, 0, 'm');
                logScan(signatures[i], path, 0, 'm');
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
    struct dirent *pDirectoryEntry;              
                
    // opens the directory
    DIR *pDirectory = opendir(path);

    // for each entry in the directory
    while (pDirectoryEntry = readdir(pDirectory)) {
        // ignore . and .. and hidden files beginning with .
        if (pDirectoryEntry->d_name[0] != '.') {

            char newPath[MAX_PATH+1] = "";                                              // +1 for null char
            sprintf(newPath, "%s/%s", path, pDirectoryEntry->d_name);
            printf("Path detected: %s\n", newPath);

            // check if entry is a file or directory
            if (isFile(newPath)) {
                result += sigScanF(signatures, sigCount, newPath);
            }
            else if (isDir(newPath)) {
                result += sigScanDir(signatures, sigCount, newPath);
            }
        }
    }

    closedir(pDirectory);
    
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
        printf("No argument given!\n");
    } 
    else if (argc > 1) {
        logScan(NULL, NULL, 0, 't');
        int noOfThreats = 0;

        // path is at argv[1], check if path is a reg file or a dir
        if (isFile(argv[1])) {
            printf("Path given is a file.\n");
        
            // scan the file for signatures
            noOfThreats = sigScanF(signatures, numOfSignatures, argv[1]);
        }
        else if (isDir(argv[1])) {
            printf("Path given is a directory.\n");

            // scan directory
            noOfThreats = sigScanDir(signatures, numOfSignatures, argv[1]);
        }
        else {
            printf("No such file or directory exists!\n");
        }
        
        printScan(NULL, NULL, noOfThreats, 'c');
        logScan(NULL, NULL, noOfThreats, 'c');
    }

    return 0;
}