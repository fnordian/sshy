#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include "connect.h"

int findFreeFdSlotReturnsFreeSlots() {
    int i;
    
    for (i = 0; i < 1; i++) {
	int freeSlot = findFreeFdSlot();
	
	if (i != freeSlot) {
	  return 1;
	}
    }
    
    return 0;
}

int wrapFdFillsSlot() {
    int freeSlot;
    int fd = 123;
    
    freeSlot = findFreeFdSlot();
    
    wrapFd(fd);
    
    if (findFreeFdSlot() != freeSlot) {
	return 0;
    } else {
	return 1;
    }
}

int findWrappedFdSlot() {

    int freeSlot;
    int fd = 124;
    
    freeSlot = findFreeFdSlot();
    
    wrapFd(fd);
    
    int wrappedFdSlot = findFdWrappedSlot(fd);
    
    if (wrappedFdSlot == freeSlot) {
        return 0;
    }
  
    return 1;
}

int getHostnameFromAddress() {
    
    struct hostent *hostent;
    void *addr;
    int addrlen;
    char hostnamebuf[100];
    char *result;
    
    hostent = gethostbyname("178.63.16.170");
    
    addr = hostent->h_addr_list[0];
    addrlen = hostent->h_length;
    
    result = hostnameFromAddress(hostnamebuf, sizeof(hostnamebuf), addr, addrlen, AF_INET);

    if (result) {
        return 0;
    } else {
        fprintf(stderr, "result: %s\n", result);
        return 1;
    }
}

void test(const char *description, int result) {
    fprintf(stderr, "%s: [%s]\n", description, result ? "failed" : "succeeded");
    if (result) {
      exit(1);
    }
}

void runTests() {
    
    test("find free slots", findFreeFdSlotReturnsFreeSlots());
    test("wrap fd fills up free slot", wrapFdFillsSlot());
    test("find wrapped fd slot", findWrappedFdSlot());
    test("get hostname from address", getHostnameFromAddress());
}


int main(int argc, char **argv) {
  
  fprintf(stderr, "/------- testrun ----------\\\n\n");
  
  runTests();
  
  fprintf(stderr, "\n\\__________________________/\n\n");
  
  return 0;
}