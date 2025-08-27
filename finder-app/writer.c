#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

int main(int argc, char *argv[])  {
    //char *file_name = NULL;
    openlog(argv[0], LOG_PID | LOG_CONS, LOG_USER);
    if (argc !=3){
         syslog(LOG_ERR, "%s", "Error: parameter is missing\n");
         return 1;
    }

    char *file_name = argv[1];
    char *file_contents = argv[2];

    FILE *file = fopen(file_name, "w");

    if (file_name == NULL) {
        syslog(LOG_ERR, "%s", "Memory allocation failed!\n");
        return 1; // Indicate an error
    }

    // check if the file was openned succesfully
    if (file == NULL) {
        syslog(LOG_ERR, "%s", "Error: Could not open the file.\n");
        return 1;
    }
    
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Writing %s to %s \n", file_contents, file_name);
    // Write the message to syslog
    syslog(LOG_DEBUG,  "Writing %s to %s \n", file_contents, file_name);
    // Close syslog
    closelog();
    // write a string to a file
    fprintf(file, "%s\n", file_contents);
    // close file
    fclose(file);
    return 0;

}