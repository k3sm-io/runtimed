/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * sysvhelper: applies a pod profile to itself (sandbox_init, never a nested
 * sandbox-exec) and then exercises System V IPC and POSIX shared memory the
 * way a workload does, printing one "<op> <result>" line per call, where the
 * result is "ok", "id <n>" or "err <errno>". The gate
 * (TestNativePodSysVIPCIsConsistent) reads the lines and removes, unconfined,
 * any object a create left behind.
 *
 * usage: sysvhelper <profile|-> <shm-name>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <unistd.h>

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);

static void rc(const char *op, int r) {
    if (r == 0) {
        printf("%s ok\n", op);
    } else {
        printf("%s err %d\n", op, errno);
    }
}

static int created(const char *op, int id) {
    if (id < 0) {
        printf("%s err %d\n", op, errno);
    } else {
        printf("%s id %d\n", op, id);
    }
    return id;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: sysvhelper <profile|-> <shm-name>\n");
        return 2;
    }
    if (strcmp(argv[1], "-") != 0) {
        static char buf[1 << 20];
        FILE *f = fopen(argv[1], "r");
        if (f == NULL) {
            perror("open profile");
            return 2;
        }
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        char *err = NULL;
        if (sandbox_init(buf, 0, &err) != 0) {
            fprintf(stderr, "sandbox_init: %s\n", err != NULL ? err : "?");
            return 3;
        }
    }

    int shm = created("shmget", shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600));
    if (shm >= 0) {
        void *p = shmat(shm, NULL, 0);
        rc("shmat", p == (void *)-1 ? -1 : 0);
        if (p != (void *)-1) {
            shmdt(p);
        }
        struct shmid_ds ds;
        rc("shmctl-stat", shmctl(shm, IPC_STAT, &ds));
        rc("shmctl-rmid", shmctl(shm, IPC_RMID, NULL));
    }

    int sem = created("semget", semget(IPC_PRIVATE, 1, IPC_CREAT | 0600));
    if (sem >= 0) {
        struct sembuf b = {0, 1, IPC_NOWAIT};
        rc("semop", semop(sem, &b, 1));
        rc("semctl-rmid", semctl(sem, 0, IPC_RMID));
    }

    int msg = created("msgget", msgget(IPC_PRIVATE, IPC_CREAT | 0600));
    if (msg >= 0) {
        rc("msgctl-rmid", msgctl(msg, IPC_RMID, NULL));
    }

    int fd = shm_open(argv[2], O_CREAT | O_EXCL | O_RDWR, 0600);
    rc("shm_open", fd < 0 ? -1 : 0);
    if (fd >= 0) {
        close(fd);
        shm_unlink(argv[2]);
    }
    return 0;
}
