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
 * semhelper: the child process TestNativeProfileAllowsOwnPosixSemaphores runs.
 *
 *   semhelper <profile.sb | -> <op> <name>
 *
 * It reads the profile, applies it to ITSELF with sandbox_init (so the test
 * never nests sandbox-exec), then performs one operation and prints one line:
 *   create  sem_open(name, O_CREAT|O_EXCL, 0600, 0), leaving it in place
 *   cycle   create, post, wait, close, unlink
 *   open    sem_open(name, 0)
 *   unlink  sem_unlink(name)
 * The line is "ok" or "err <errno>". A profile of "-" applies nothing.
 */

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);

static int report(int rc) {
    if (rc == 0) {
        printf("ok\n");
    } else {
        printf("err %d\n", errno);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: semhelper <profile|-> <op> <name>\n");
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
    const char *op = argv[2], *name = argv[3];
    if (strcmp(op, "create") == 0) {
        sem_t *s = sem_open(name, O_CREAT | O_EXCL, 0600, 0);
        return report(s == SEM_FAILED ? -1 : 0);
    }
    if (strcmp(op, "open") == 0) {
        sem_t *s = sem_open(name, 0);
        return report(s == SEM_FAILED ? -1 : 0);
    }
    if (strcmp(op, "unlink") == 0) {
        return report(sem_unlink(name));
    }
    if (strcmp(op, "cycle") == 0) {
        sem_t *s = sem_open(name, O_CREAT | O_EXCL, 0600, 0);
        if (s == SEM_FAILED || sem_post(s) != 0 || sem_wait(s) != 0 || sem_close(s) != 0 ||
            sem_unlink(name) != 0) {
            return report(-1);
        }
        return report(0);
    }
    fprintf(stderr, "unknown op %s\n", op);
    return 2;
}
