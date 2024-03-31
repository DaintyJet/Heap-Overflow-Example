// Sourced from https://www.rapid7.com/blog/post/2019/06/12/heap-overflow-exploitation-on-windows-10-explained/

// Windows Functionality
#include <Windows.h>
// C Standard Input and Output Library
#include <stdio.h>

// Defined Chunk Size 16^2 * 3 = 768 Bytes 
#define CHUNK_SIZE 0x300

int main(int args, char** argv) {
    int i;
    LPVOID chunk;
    // Get a default process HEAP handle
    HANDLE defaultHeap = GetProcessHeap();

    // Trigger LFH
    for (i = 0; i < 18; i++) {
        // Preform 18 allocations on the heap
        HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
    }

    // Trigger LFH Heuristics, allocate in LFH
    chunk = HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
    printf("New chunk in LFH : 0x%08x\n", chunk);

    // Free a block of memory, not sure of why HEAP_NO_SERIALIZE is used
    // If using the process heap it should not be used. 
    BOOL result = HeapFree(defaultHeap, HEAP_NO_SERIALIZE, chunk);
    printf("HeapFree returns %d\n", result);

    // Allocate a new chunk, is it a reused chunk?
    chunk = HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
    printf("Another new chunk : 0x%08x\n", chunk);

    // Pause
    system("PAUSE");
    return 0;
}