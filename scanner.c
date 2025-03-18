#include <stdio.h>
#include <ctype.h>
#include <string.h>
#define BUFFER_SIZE 1024

void strToLower(char *str) {
    // modify str in place
    int length = strlen(str);

    for (int i = 0; i < length; i++) {
        str[i] = tolower(str[i]);
    }

    return;
}

int main() {
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
    FILE *pFile = fopen("test.txt", "r");

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

    return 0;
}