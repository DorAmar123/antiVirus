#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dirent.h"

#define MAX_PATH_SIZE 100
#define TWENTY_PERCENT_DIVISOR 5
#define WHERE_VIRUS_MSG_SIZE 15

void generalScan(char *dirPath,char *virusFilePath,int scanType,FILE* logFile);
int normalScan(FILE* searchedFile,FILE* virusFile);
long int checkSize(FILE* file);
void quickScan(char *searchedFilePath,FILE* virusFile,FILE* logFile);

int main(int argc, char** argv)
{
    char logFilePath[MAX_PATH_SIZE] = {0};
    FILE* logFile = NULL;
    int choice=0;

    strcpy(logFilePath,argv[1]);
    strcat(logFilePath,"/AntiVirusLog.txt");//Composes the full path of the file.
    logFile=fopen(logFilePath, "w");
    if (logFile == NULL)
    {
        printf("Error opening file");
        return 1;
    }

    printf("Welcome to my Virus Scan!\n\n");
    fprintf(logFile,"Anti-virus began! Welcome!\n\n");

    printf("Folder to scan: %s\n",argv[1]);
    printf("Virus signature: %s\n\n",argv[2]);
    fprintf(logFile,"Folder to scan:\n%s\nVirus signature:\n%s\n\n",argv[1],argv[2]);

    printf("Press 0 for a normal scan or any other key for a quick scan: ");
    fprintf(logFile,"Scanning option:\n");
    scanf("%d",&choice);
    printf("Scanning began...\nThis process may take several minutes...\n\nScanning:\n");
    generalScan(argv[1],argv[2],choice,logFile);
    getchar();
    
    printf("Scan Completed.\n");
    fclose(logFile);
    printf("See log path for results: %s\n",logFilePath);
    getchar();
    return 0;
}
/*
    The function scans a folder according to the user's selection and checks whether the virus signature appears in each of the files in it.
    input: the path of the directory, the path of the file with the virus signature, the user's scan selection and the log file into which all the information about the scan is written.
    output: none
*/
void generalScan(char *dirPath,char *virusFilePath,int scanType,FILE* logFile)
{
    DIR* dir = opendir(dirPath);
    FILE* virusFile=NULL;
    FILE* currentFile=NULL;
    struct dirent* dirStruct = 0;
    int size=0;
    char **paths=(char**) malloc (sizeof(char*)*0);
    char fullPath[MAX_PATH_SIZE]={0};
    char *temp=NULL;
    int i=0;



    while ((dirStruct = readdir(dir)) != NULL)//Arranges the directory so that it is in alphabetical order
    {
        if(strcmp(dirStruct->d_name, ".") && strcmp(dirStruct->d_name, "..") && dirStruct->d_type != DT_DIR)
        {
            strcpy(fullPath,dirPath);
            strcat(fullPath,"/");
            strcat(fullPath,dirStruct->d_name);//Composes the full path of the file.

            size++;
            paths=(char**)realloc(paths,size*sizeof(char*));//Uses realloc to increase the array;
            if(!paths)
            {
                printf("Unsuccessful realloc!");
                exit(1);
            }
            paths[size-1] = (char*)malloc(strlen(fullPath) + 1);
            if(!paths[size-1])
            {
                printf("Unsuccessful malloc!");
                exit(1);
            }
            strcpy(paths[size-1],fullPath);
            for ( i = size-1; i > 0; i--)
            {
                if(strcmp(paths[i],paths[i-1])<0)
                {
                    temp = paths[i];
                    paths[i] = paths[i - 1];
                    paths[i - 1] = temp;
                }
            }

        }
    }
    if(scanType==0)//normal scan
    {
        fprintf(logFile,"Normal Scan\n\nResults:\n");

        for(i = 0; i < size; i++)
        {
            currentFile=fopen(paths[i], "rb");
            virusFile=fopen(virusFilePath, "rb");

            if (currentFile == NULL||virusFile  == NULL)//Checks if files exist
            {
                printf("%s - Error opening file\nReading Error\n",paths[i]);
                fprintf(logFile,"%s Reading Error\n",paths[i]);
            }
            else if(normalScan(currentFile,virusFile))
            {
                printf("%s - Infected!\n",paths[i]);
                fprintf(logFile,"%s - Infected!\n",paths[i]);
            }
            else
            {
                printf("%s - Clean\n",paths[i]);
                fprintf(logFile,"%s - Clean\n",paths[i]);
            }
            fclose(currentFile);
            fclose(virusFile);
        }

    }
    else//quick scan
    {
        fprintf(logFile,"Quick Scan\n\nResults:\n");
        for(i = 0; i < size; i++)
        {
            virusFile=fopen(virusFilePath, "rb");
            quickScan(paths[i],virusFile,logFile);
            fclose(virusFile);
        }
    }

    for (i = 0; i < size; i++) 
    {
        free(paths[i]);
    }
    free(paths);
    closedir(dir);
}

/*
    The function Checks in the usual way whether the virus signature appears in the file
    input: the file to check and the file with the virus signature
    output: 0 if the file is clean or 1 if he is infected
*/
int normalScan(FILE* searchedFile,FILE* virusFile)
{
    int found=0;
    long int searchedFileSize=checkSize(searchedFile);
    long int virusSize=checkSize(virusFile);
    char* searchedBuffer = NULL;  
    char* virusBuffer = NULL;
    long int i=0;

    if(virusSize>searchedFileSize)
    {   
        found=0;
    }
    else
    {
        searchedBuffer = (char*) malloc (sizeof(char)*searchedFileSize);
        virusBuffer = (char*) malloc (sizeof(char)*virusSize);
        if(!searchedBuffer||!virusBuffer)
        {
            printf("Unsuccessful malloc!");
            exit(1);
        }
        fread(searchedBuffer,sizeof(char),searchedFileSize,searchedFile);
        fread(virusBuffer,sizeof(char),virusSize,virusFile);

        for (i = 0; i < searchedFileSize&&!found; i++)
        {
            if (memcmp(searchedBuffer+i,virusBuffer,virusSize) == 0)
            {
                found=1;
            }
        }
        free(searchedBuffer);
        free(virusBuffer);
    }
    return found;
}
/*
    The function Checks in the quick way whether the virus signature appears in the file and find where he is exactly
    input: the path to the searched file, the file with the virus signature and the log file into which all the information about the scan is written.
    output: none
*/
void quickScan(char *searchedFilePath,FILE* virusFile,FILE* logFile)
{
    FILE* searchedFile=fopen(searchedFilePath, "rb");
    long int searchedFileSize=checkSize(searchedFile);
    long int virusSize=checkSize(virusFile);
    char* searchedBuffer = NULL;  
    char* virusBuffer = NULL;
    long int bufferSize = searchedFileSize/TWENTY_PERCENT_DIVISOR;
    int found = 0;
    char where[WHERE_VIRUS_MSG_SIZE] = {0};
    int i=0;

    if(searchedFile == NULL||virusFile  == NULL)
    {
        printf("%s - Error opening file\nReading Error\n",searchedFilePath);
        fprintf(logFile,"%s Reading Error\n",searchedFilePath);
    }
    else if(virusSize>searchedFileSize)
    {
        printf("%s - Clean\n",searchedFilePath);
        fprintf(logFile,"%s - Clean\n",searchedFilePath);
    }
    else
    {
        searchedBuffer = (char*) malloc (sizeof(char)*searchedFileSize);
        virusBuffer = (char*) malloc (sizeof(char)*virusSize);
        if(!searchedBuffer||!virusBuffer)
        {
            printf("Unsuccessful malloc!");
            exit(1);
        }

        fseek(searchedFile, searchedFileSize-bufferSize, SEEK_SET);
        fread(searchedBuffer,sizeof(char),bufferSize,searchedFile);
        fread(virusBuffer,sizeof(char),virusSize,virusFile);

        for (i = 0; i < bufferSize&&!found; i++)
        {
            if (memcmp(searchedBuffer+i,virusBuffer,virusSize) == 0)
            {
                found=1;
                strcpy(where," (last 20%)");
            }
        }
        if(!found)
        {
            free(searchedBuffer);
            searchedBuffer = (char*) malloc (sizeof(char)*searchedFileSize);
            if(!searchedBuffer)
            {
                printf("Unsuccessful malloc!");
                exit(1);
            }
            fseek(searchedFile, 0, SEEK_SET);
            fread(searchedBuffer,sizeof(char),searchedFileSize,searchedFile);
            for (i = 0; i < searchedFileSize&&!found; i++)
            {
                if(i<bufferSize)
                {
                    if (memcmp(searchedBuffer+i,virusBuffer,virusSize) == 0)
                    {
                        found=1;
                        strcpy(where," (first 20%)");
                    }
                }
                else if(memcmp(searchedBuffer+i,virusBuffer,virusSize) == 0)
                {
                    found=1;
                    strcpy(where,"");
                }
                
            }
        }
        if(found)
        {
            printf("%s - Infected!%s\n",searchedFilePath,where);
            fprintf(logFile,"%s - Infected!%s\n",searchedFilePath,where);
        }
        else
        {
            printf("%s - Clean\n",searchedFilePath);
            fprintf(logFile,"%s - Clean\n",searchedFilePath);
        }
        free(searchedBuffer);
        free(virusBuffer);

    }
    fclose(searchedFile);
}
/*
    The function checkes the size of a file
    input: the file
    output: the size
*/
long int checkSize(FILE* file)
{
    long int size=0;
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}
/*
    The function memcmp() is compare two blocks of data(in bytes) by their pointers
    Syntax: memcmp( p1, p2, n);
    input: the two pointers and the number of bytes to compare
    output: 0 when the two blocks are equal, negative when the first pointer is less then the second and positive when the opposite
*/
/*
    The function fprintf() is used to write text to a file.
    It works like the printf() function, but instead of printing the text, it writes it to a file.
    Syntax: fprintf(FILE *file, const char *str, ...);
    input: The file you want to write to and the text you want to write.
    output: The number of characters written or a negative number if an error occurred.
*/