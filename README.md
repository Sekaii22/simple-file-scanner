# simple-file-scanner

Scans a file or directory for predefined malware signatures (specific strings found in known malware). It will check if a file contains a suspicious string and alert the user.

Use the other available branch for fuzzy hash generation on files.

Compilation on Linux (Ubuntu):

    $ gcc -o scanner scanner.c

Run it with the command: 
    
    $ ./scanner <filename>