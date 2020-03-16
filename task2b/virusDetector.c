#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

typedef struct link link;
 


typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    char* sig;
} virus;


struct link {
    link *nextVirus;
    virus *vir;
};

void startTheLoop();
void list_print(); 
void list_append(virus* data); 
void list_free();
void loadSignatures ();
void quit();
void printVirusSig();
void recursiveFree(link * pos);
int countViruses (char * buffer, long length);
void detect_virus(char *buffer, unsigned int size);
void prepareToDetect();
void prepareToKillVirus();
void kill_virus(char *fileName, int signitureOffset, int signitureSize);



struct link * virusList;


void startTheLoop()
{
    char input[4];
    int option;
    
    
    fprintf(stderr, "1) Load signatures\n2) Print signatures\n3) Detect viruses\n4) Fix file\n5) Quit\n");
    while (0 != 1)
    {
        fprintf(stderr, "Please choose a function:\n");
        
        fflush(stdin);
        fseek(stdin,0,SEEK_END);
        fgets(input, 4, stdin);
        sscanf(input, "%d", &option);

        if (option == 1)
        {
            loadSignatures();
        }
        else if (option == 2) 
        {
             list_print();
        }
        else if (option == 3)
        {
             prepareToDetect();
        }
        else if (option == 4)
        {
             prepareToKillVirus();
        }
        else if (option == 5)   
        {
              quit();
        }
        else
        {
            fprintf(stderr, "Invalid Option\n");
            exit(0);
        }
    }
}



void loadSignatures ()
{
    fprintf(stderr, "Input A File Name:\n");
    char fileName[256];
    scanf("%s", fileName);
    fgetc(stdin);
    
    fflush(stdin);
    fseek(stdin,0,SEEK_END);
    
    FILE * filePointer = fopen(fileName, "r");
    fseek (filePointer , 0 , SEEK_END);
    long length = ftell (filePointer);
    fseek(filePointer, 0, SEEK_SET);
    int numberOfViruses = 0;
    
    fseek(filePointer, 0, SEEK_SET);
    char * buffer;
    buffer = (char *)malloc(sizeof(char) * length);
    
    size_t status = fread(buffer, 1, length, filePointer);
    if (status != length)
    {
        fprintf(stderr, "Error of Reading");
        exit(1);
    }
    numberOfViruses = countViruses(buffer, length);
    
    
    int zeroPoint = 0;
    int virusNumber = 0;
    
    char ch1, ch2;
    int i1, i2;
    
    int integerSigSize;
    
    struct virus * data;
    
    char * sig;

    for (int i=0; i<numberOfViruses; i++)
    {
        data = (struct virus *)malloc(sizeof(struct virus));
/*        
        ms = (int)buffer[zeroPoint+1];
        ls = (int)buffer[zeroPoint];
        integerSigSize = ms*256 + ls - 18;
        */
        
        ch1 = buffer[zeroPoint];
        ch2 = buffer[zeroPoint+1];
        
        i1 = (int)ch1;
        i2 = (int)ch2;
        if (i1 < 0)
        {
            i1 += 256;
        }
        if (i2 < 0)
        {
            i2+=256;
        }
        
        integerSigSize = (i1 * 1) + (i2 * 256) - 18;
        
        data->SigSize = (unsigned short)integerSigSize;

        for (int j=0; j<16; j++)
        {
            data->virusName[j] = buffer[zeroPoint + 2 + j];
        }
        
        sig = (char *)malloc(sizeof(char) * integerSigSize);
        
        for (int k=0; k<integerSigSize; k++)
        {
             sig[k] = buffer[zeroPoint + 18 + k];
        }


        data->sig = sig;
        list_append(data);
        
        zeroPoint += (int)(data->SigSize)+18;
        virusNumber++;
    }
    

    free(buffer);
    fclose(filePointer);
    
}


int countViruses (char * buffer, long length)
{
    int numberOfViruses = 0;
    int index = 0;
    char ch1, ch2;
    int i1, i2;
    int addOffset = 0;
//     short size;
    while(index<length)
    {
        ch1 = buffer[index];
        ch2 = buffer[index+1];
        
        i1 = (int)ch1;
        i2 = (int)ch2;
        
        
        if (i1 < 0)
        {
            i1 += 256;
        }
        if (i2 < 0)
        {
            i2+=256;
        }
        
        
        /*
    fread(&size, sizeof(short), 1, buffer[index]);
    fprintf(stderr, "size = %d", size);
        */
        
        addOffset = (i1 * 1) + (i2 * 256);
        
        
        index += addOffset;
        numberOfViruses++;
    }
    return numberOfViruses;
}

void list_append(virus* data)
{
    struct link * current = virusList;
    
    struct link * newLink = (struct link *)malloc(sizeof(struct link));
    newLink->vir = data;
    newLink->nextVirus = NULL;
    
    if (virusList == NULL)
    {
        virusList = newLink;
    }
    else
    {
        while (current->nextVirus != NULL)
        {
            current = current->nextVirus;
        }
        current->nextVirus = newLink;
    }
}
         
void list_print()
{
    struct link * pos = virusList;
    while (pos != NULL)
    {
        fprintf(stderr, "Virus name: %s\n", pos->vir->virusName);
        fprintf(stderr, "Virus size: %d\n", pos->vir->SigSize);
        fprintf(stderr, "signature:\n");
         printVirusSig(pos);
        fprintf(stderr, "\n\n");
        
        pos = pos->nextVirus;
    }
    
}

void printVirusSig(struct link * pos)
{
    int SigSize = pos->vir->SigSize;
    for(int i=0; i<SigSize; i++)
    {
        if(i != 0)
        {
            if (i%20 == 0)
            {
                fprintf(stderr, "\n");
            }
            else
            {
                fprintf(stderr, " ");
            }
        }        
         fprintf(stderr, "%02hhX" ,(int) (*(unsigned char *) (& pos->vir->sig[i])));

    }
}

void quit()
{
    recursiveFree(virusList);
    exit(0);
}

void recursiveFree(struct link * pos)
{
    if (pos != NULL)
    {
        recursiveFree(pos->nextVirus);
        free(pos->vir->sig);
        free(pos->vir);
        free(pos);
    }
}


void prepareToDetect ()
{
    fprintf(stderr, "Input A Suspected File Name:\n");
    char fileName[256];
    scanf("%s", fileName);
    fgetc(stdin);
    fflush(stdin);
    fseek(stdin,0,SEEK_END);
    FILE * filePointer = fopen(fileName, "r");
    fseek (filePointer , 0 , SEEK_END);
    long length = ftell (filePointer);
    fseek(filePointer, 0, SEEK_SET);
    char * buffer;
    buffer = (char *)malloc(sizeof(char) * length);
    size_t status = fread(buffer, 1, length, filePointer);
    if (status != length)
    {
        fprintf(stderr, "Error of Reading Suspected File\n");
        exit(1);
    }
    
    unsigned int size;
    if (length < 10240)
    {
        size = length;
    }
    else
    {
        size = 10240;
    }
    
     detect_virus(buffer,size);
    
    
    free(buffer);
    fclose(filePointer);
}

void detect_virus(char *buffer, unsigned int size)
{
    struct link * pos;
    int result;
    unsigned short SigSize;
    int charachtersLeft;
    
    for (int i=0; i<size; i++)
    {
        pos = virusList;
        while (pos != NULL)
        {
            SigSize = pos->vir->SigSize;
            charachtersLeft = size-i;
            
            
            if (SigSize <= charachtersLeft)
            {
                result = memcmp(pos->vir->sig, buffer+i, SigSize);
                if (result == 0)
                {
                    
                    fprintf(stderr, "Byte Number: %d\n", i);
                    fprintf(stderr, "Virus name: %s\n", pos->vir->virusName);
                    fprintf(stderr, "Virus size: %d\n", pos->vir->SigSize);                        fprintf(stderr, "\n");
                }
            }
            
            pos = pos->nextVirus;
        }
    }
    
}


void prepareToKillVirus()
{
         char input1[32];
         char input2[32];
//         char input[256];
    int sigSize;
    int startingByteLocation;
        
    fprintf(stderr, "Input A File Name To Fix:\n");
    char fileName[256];
    scanf("%s", fileName);
    fgetc(stdin);
    fflush(stdin);
    fseek(stdin,0,SEEK_END);
    
    
    
        
    fprintf(stderr, "Enter Starting Byte Location:\n");
    scanf("%s", input1);
    startingByteLocation = atoi(input1);
    
    
    fprintf(stderr, "Enter Signutare Size:\n");
    scanf("%s", input2);
    sigSize = atoi(input2);
    
    
    
    kill_virus(fileName, startingByteLocation, sigSize);
    
    
}
void kill_virus(char *fileName, int signitureOffset, int signitureSize)
{

    FILE * filePtr = fopen(fileName, "r+");
//     FILE * filePointer = fopen(fileName, "r");
    
    
       

//     unsigned char fix = (unsigned char)144;
    
    

    fprintf(stderr, "signitureOffset = %d\nsignitureSize = %d\n",signitureOffset,signitureSize);

    
    
    
       fseek(filePtr,signitureOffset, SEEK_SET);
       
       
     char buf[signitureSize];
     memset(buf,0,signitureSize);

            fprintf(stderr, "FLAG 1\n");
            
    fwrite(buf,signitureSize,1, filePtr+signitureOffset);
       
    
    char * nops = (char *)malloc(sizeof(char) * 8);
    
    nops= 0xC3;
        fwrite(nops,1,1, filePtr+signitureOffset);
    
    
        fprintf(stderr, "FLAG 2\n");
    fclose(filePtr);
}



int main(int argc, char **argv)
{
    virusList = NULL;
    startTheLoop();
    return 0;
}























