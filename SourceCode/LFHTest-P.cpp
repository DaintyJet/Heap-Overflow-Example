// Sourced and slightly modified from https://www.rapid7.com/blog/post/2019/06/12/heap-overflow-exploitation-on-windows-10-explained/

// Windows Functionality
#include <Windows.h>
// C Standard Input and Output Library
#include <stdio.h>

// Defined Chunk Size 16^2 * 3 = 768 Bytes 
#define CHUNK_SIZE 0x300

int main(int args, char** argv) {
    int i;
    LPVOID chunk;

    // Store Previous Chunk
    LPVOID pchunk;
    
    // Get a default process HEAP handle
    HANDLE defaultHeap = GetProcessHeap();

    // Preform 18 allocations of the same size (<16Kb)
    for (i = 0; i < 18; i++) {
        if(i > 0)
            pchunk = chunk;

        // Allocate objects onto the heap
        chunk = HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
        printf("[%d] Chunk is at: 0x%p", i, chunk);
        
        if(i > 0)
            printf(", with a difference of 0x%lx between addresses\n", ((long)chunk - (long)pchunk));
        else 
            printf("\n");
                
    }

    // Preform LFH allocations
    // We have likely triggered the heuristics
    for (i = 0; i < 5; i++) {
        
        if(i > 0)
            pchunk = chunk;

        // Allocate objects onto the heap
        chunk = HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
        printf("[%d] New chunk in LFH: 0x%p", i ,chunk);
        
        if(i > 0)
            printf(", with a difference of 0x%lx between addresses\n", ((long)chunk - (long)pchunk));
        else 
            printf("\n");
    }

    // Pause! (User input will be needed before the process exits)
    system("PAUSE");
    return 0;
}