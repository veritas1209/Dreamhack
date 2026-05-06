#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#define MAX_TYPES 5
#define MAX_DEG 63

int degrees[5] = {1, 7, 15, 31, 63};

struct random_state {
    uint32_t type;
    uint32_t array[MAX_DEG];
};

struct random_state *generate_random_state(int type) {
    if (type < 0 || type >= MAX_TYPES)
        return NULL;

    struct random_state *state = (struct random_state *) malloc(sizeof(struct random_state));

    // Set type
    state->type = (uint32_t) type;

    // Set state
    ssize_t read = getrandom(state->array, sizeof(uint32_t) * degrees[type], 0);
    if (read != sizeof(uint32_t) * degrees[type]) {
        free(state);
        return NULL;
    }

    if (type == 0)
        state->array[0] &= 0x7FFFFFFF;

    return state;
}

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    struct random_state initial_state_copy;

    int challenges[MAX_TYPES][2] = {
        {100, 1},
        {7 * 50, 7 * 5},
        {15 * 50, 15 * 5},
        {31 * 50, 31 * 10},
        {63 * 50, 63 * 10},
    };

    for (int type = 0; type < MAX_TYPES; type++) {
        printf("Guess type %d!\n", type);

        struct random_state *state = generate_random_state(type);
        if (!state) {
            printf("Something wrong :(\n");
            return 1;
        }
        memcpy(&initial_state_copy, state, sizeof(struct random_state));
        setstate((char *)state);

        for (int i = 0; i < challenges[type][0]; i++)
            rand();

        for (int i = 0; i < challenges[type][1]; i++) {
            printf("%u ", rand());
            if (i % 10 == 9 || i == challenges[type][1] - 1)
                printf("\n");
        }

        printf("Guess? (total %d required)\n", degrees[type]);
        for (int i = 0; i < degrees[type]; i++) {
            uint32_t v;
            scanf("%u", &v);

            if (v != initial_state_copy.array[i]) {
                printf("Wrong guess :( %u\n", initial_state_copy.array[i]);
                return 1;
            }
        }

        printf("Nice!\n");
    }

    // Read flag
    printf("Congratulation!!!\nHere is the flag: ");

    FILE *f = fopen("./flag", "r");
    if (!f) {
        printf("Failed to read the flag file. Ask admin.\n");
        return 1;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t len = getline(&line, &cap, f);
    if (len > 0)
        fwrite(line, 1, len, stdout);
    free(line);
    fclose(f);

    return 0;
}