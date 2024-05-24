#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <semaphore.h>

#define BUFF_SIZE 64
#define N_THREAD 64
#define FLAG_ID 34
const int64_t KEY = 0x1337dead1337beef;
const char CHARS[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX{}_!";
char FLAG[N_THREAD + 1];

sem_t dispact_sem;

struct tx_pck {
    int64_t **buff;
    sem_t mutex;
    int status;
};

struct t_arg {
    int id;
    struct tx_pck *pool;
};

void *t1(void *t_arg);
void *t2(void *t_arg);

int main(int argc, char *argv[]) {
    if (argc < 2)
        exit(1);
    strncpy(FLAG, argv[1], N_THREAD);

    pthread_t threads[N_THREAD];
    struct t_arg args[N_THREAD];
    struct tx_pck stream[256];

    for (int i = 0; i < 256; i++) {
        stream[i].buff = NULL;
        stream[i].status = 0;
        sem_init(&stream[i].mutex, 0, 0);
    }

    int seed;
    FILE *urand;
    urand = fopen("/dev/urandom", "rb");
    fread(&seed, sizeof(seed), 1, urand);
    fclose(urand);
    srand(seed);

    pthread_t sender_t;
    sem_init(&dispact_sem, 0, 0);
    pthread_create(&sender_t, NULL, t2, &stream);

    for (int i = 0; i < N_THREAD; i++) {
        args[i].id = i;
        args[i].pool = stream;
        pthread_create(&threads[i], NULL, t1, &args[i]);
    }

    pthread_join(sender_t, NULL);
    sem_destroy(&dispact_sem);

    return 0;
}

int64_t** x() {
    int64_t **ptr = (int64_t**)malloc(BUFF_SIZE * sizeof(int64_t*));
    if (ptr == NULL) {
        fprintf(stderr, "malloc(1) failed\n");
        exit(1);
    }
    for (int i = 0; i < BUFF_SIZE; i++) {
        ptr[i] = (int64_t*)calloc(BUFF_SIZE, sizeof(int64_t));
        if (ptr[i] == NULL) {
            fprintf(stderr, "malloc(2) failed\n");
            exit(1);
        }
    }
    return ptr;
}

void k(int64_t **buff) {
    for (int i = 0; i < BUFF_SIZE; i++) {
        for (int j = 0; j < BUFF_SIZE; j++) {
            buff[i][j] ^= KEY;
        }
    }
}

void y(int64_t **ptr) {
    for (int i = 0; i < BUFF_SIZE; i++)
        free(ptr[i]);
    free(ptr);
}

void o(int64_t **buff) {
    for (int i = 0; i < BUFF_SIZE; i++) {
        fwrite(buff[i], sizeof(int64_t), BUFF_SIZE, stdout);
    }
}

void *t1(void *t_arg) {
    struct t_arg *arg = (struct t_arg*)t_arg;
    char filename[32];
    FILE *f;
    int16_t buffer[BUFF_SIZE];

    sprintf(filename, "./codes/%d.bin", arg->id);
    f = fopen(filename, "rb");

    uint64_t code;
    fread(&code, sizeof(code), 1, f);
    fclose(f);

    int i = arg->id;
    do {
        if (i == arg->id) {
            arg->pool[(i<<1)].buff = x();
            arg->pool[(i<<1)+1].buff = x();
            arg->pool[(i<<1)].status = 0;
        } else
            sem_wait(&arg->pool[i<<1].mutex);

        // write my data to the segment
        if (arg->id == FLAG_ID) {
            // flag thread
            int idx = (int)(strchr(CHARS, FLAG[i]) - CHARS);
            memset(buffer, idx, BUFF_SIZE * sizeof(int16_t));
        } else {
            // not flag thread
            if (i == arg->id) {
                // my letter if my segment
                int idx = i - ((i > FLAG_ID) ? 1 : 0);
                memset(buffer, CHARS[idx], BUFF_SIZE * sizeof(int16_t));
            } else {
                // random
                for (int j = 0; j < BUFF_SIZE; j++) {
                    buffer[j] = rand() % 1024;
                }
            }
        }

        // talking on the channel
        for (int j = 0; j < BUFF_SIZE; j++) {
            for (int k = 0; k < BUFF_SIZE; k++) {
                arg->pool[(i<<1)].buff[j][k] += buffer[j] * ((code >> k) & 1 ? -1 : 1);
            }
        }
        
        // write my code in the next segment, if not flag thread
        if (arg->id != FLAG_ID && i == arg->id) {
            for (int j = 0; j < BUFF_SIZE; j++) {
                for (int k = 0; k < BUFF_SIZE; k++) {
                    arg->pool[(i<<1)+1].buff[j][k] += (((arg->id+1) >> j)&1) * ((code >> k)&1);
                }
            }
        }

        arg->pool[(i<<1)].status++;
        if (arg->pool[(i<<1)].status == N_THREAD)
            sem_post(&dispact_sem);
        sem_post(&arg->pool[(i<<1)].mutex);

        i++;
        i %= 64;
    } while(i != arg->id);
}

void *t2(void *t_arg) {
    struct tx_pck* buffers = (struct tx_pck*)t_arg;

    // encrypt and send each segment when ready
    int processed = 0;
    while (processed != N_THREAD) {
        sem_wait(&dispact_sem);
        processed++;
    }
        
    for (int i = 0; i < N_THREAD; i++) {
        // encrypt
        k(buffers[(i<<1)].buff);
        k(buffers[(i<<1)+1].buff);

        // send
        o(buffers[(i<<1)].buff);
        o(buffers[(i<<1)+1].buff);

        // cleanup
        y(buffers[(i<<1)].buff);
        y(buffers[(i<<1)+1].buff);
        sem_destroy(&buffers[(i<<1)].mutex);
        sem_destroy(&buffers[(i<<1)+1].mutex);
    }
}
