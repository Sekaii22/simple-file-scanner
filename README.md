# simple-file-scanner

Scans a file or directory for predefined malware signatures (specific strings found in known malware). It will check if a file contains a suspicious string and alert the user. Also generates a fuzzy hash using ssdeep when running the scanner on a file.

Compilation on Linux (Ubuntu):

    # install ssdeep
    $ sudo apt install libfuzzy-dev
    $ gcc -o scanner scanner.c -lfuzzy

Run it with the command: 
    
    $ ./scanner <filename>