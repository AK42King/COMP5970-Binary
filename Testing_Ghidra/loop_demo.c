#include <stdio.h>

void loop_function() {
    int i = 0;
    while (i < 5) {
        printf("i = %d\n", i);
        i++;
    }
}

int main() {
    loop_function();
    return 0;
}
