/*
 * k3sm path-rebase DYLD interpose shim.
 *
 * k3sm pods run as native processes at real host paths with NO chroot / mount
 * namespace (DESIGN §pod-model), so a volume mounted at an absolute container path
 * like "/etc/nats" is materialized under the pod's data volume at
 * "<rootfs>/etc/nats" — but the pod's own absolute "/etc/nats" open() reaches the
 * HOST /etc/nats, not the materialized copy. This dylib, loaded via
 * DYLD_INSERT_LIBRARIES, interposes the path-taking libc entry points and rewrites
 * an absolute path that falls under a configured mount prefix to "<rootfs><path>",
 * so a standard absolute mount path resolves to the materialized volume. Every
 * other path (/System, /usr/lib, /bin, and any host path NOT under a mount prefix)
 * passes through UNCHANGED — the rewrite is surgical, per declared mount prefix.
 *
 * Plain C built with clang (see ../hack/build-pathshim.sh), NOT Go cgo: a DYLD
 * interposer must be a C dylib with a __DATA,__interpose section, and runtimed's
 * pod-support artifacts stay independent of its Go build.
 *
 * Configuration comes from the environment (the runtime sets these per pod):
 *   K3SM_ROOTFS       - the pod data volume the mounts are rebased under
 *   K3SM_MOUNT_PATHS  - ':'-separated absolute mount prefixes to rebase
 *
 * If either is unset/empty the shim transparently defers to the real function for
 * every call, so a non-pod process loading it is unaffected.
 */

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------- DYLD interpose plumbing -------- */

typedef struct interpose_s {
    const void *replacement;
    const void *original;
} interpose_t;

#define K3SM_MAX_MOUNTS 64
#define K3SM_MAXPATH PATH_MAX

typedef struct {
    int enabled;
    char rootfs[K3SM_MAXPATH];
    size_t rootfs_len;
    char mounts[K3SM_MAX_MOUNTS][K3SM_MAXPATH];
    size_t mount_len[K3SM_MAX_MOUNTS];
    int nmounts;
} k3sm_pathcfg_t;

static k3sm_pathcfg_t g_cfg;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static void k3sm_pathcfg_init(void) {
    memset(&g_cfg, 0, sizeof(g_cfg));
    const char *rootfs = getenv("K3SM_ROOTFS");
    const char *mounts = getenv("K3SM_MOUNT_PATHS");
    if (rootfs == NULL || rootfs[0] != '/' || mounts == NULL || mounts[0] == '\0') {
        g_cfg.enabled = 0;
        return;
    }
    snprintf(g_cfg.rootfs, sizeof(g_cfg.rootfs), "%s", rootfs);
    /* strip a trailing slash so "<rootfs>" + "/etc/x" never doubles it */
    g_cfg.rootfs_len = strlen(g_cfg.rootfs);
    while (g_cfg.rootfs_len > 1 && g_cfg.rootfs[g_cfg.rootfs_len - 1] == '/') {
        g_cfg.rootfs[--g_cfg.rootfs_len] = '\0';
    }

    char buf[K3SM_MAX_MOUNTS * K3SM_MAXPATH];
    snprintf(buf, sizeof(buf), "%s", mounts);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ":", &save);
         tok != NULL && g_cfg.nmounts < K3SM_MAX_MOUNTS;
         tok = strtok_r(NULL, ":", &save)) {
        if (tok[0] != '/') {
            continue; /* only absolute prefixes */
        }
        size_t l = strlen(tok);
        while (l > 1 && tok[l - 1] == '/') {
            tok[--l] = '\0';
        }
        snprintf(g_cfg.mounts[g_cfg.nmounts], K3SM_MAXPATH, "%s", tok);
        g_cfg.mount_len[g_cfg.nmounts] = l;
        g_cfg.nmounts++;
    }
    g_cfg.enabled = g_cfg.nmounts > 0;
}

/*
 * If path is an absolute path at or under a configured mount prefix, write
 * "<rootfs><path>" into buf and return buf; otherwise return the original path
 * unchanged. buf must be at least K3SM_MAXPATH bytes.
 */
static const char *k3sm_rebase(const char *path, char *buf) {
    pthread_once(&g_once, k3sm_pathcfg_init);
    if (!g_cfg.enabled || path == NULL || path[0] != '/') {
        return path;
    }
    for (int i = 0; i < g_cfg.nmounts; i++) {
        size_t l = g_cfg.mount_len[i];
        if (strncmp(path, g_cfg.mounts[i], l) != 0) {
            continue;
        }
        /* exact prefix, or a '/'-bounded descendant (never a sibling like /etcX) */
        if (path[l] != '\0' && path[l] != '/') {
            continue;
        }
        if (g_cfg.rootfs_len + strlen(path) >= (size_t)K3SM_MAXPATH) {
            return path; /* would overflow — leave unrewritten, fail safe */
        }
        memcpy(buf, g_cfg.rootfs, g_cfg.rootfs_len);
        strcpy(buf + g_cfg.rootfs_len, path);
        return buf;
    }
    return path;
}

/* -------- interposed path entry points -------- */

int k3sm_open(const char *path, int flags, ...) {
    char buf[K3SM_MAXPATH];
    const char *p = k3sm_rebase(path, buf);
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = (mode_t)va_arg(ap, int);
        va_end(ap);
        return open(p, flags, mode);
    }
    return open(p, flags);
}

int k3sm_openat(int fd, const char *path, int flags, ...) {
    char buf[K3SM_MAXPATH];
    /* Only an ABSOLUTE path is rebased; a relative openat resolves against fd. */
    const char *p = (path != NULL && path[0] == '/') ? k3sm_rebase(path, buf) : path;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = (mode_t)va_arg(ap, int);
        va_end(ap);
        return openat(fd, p, flags, mode);
    }
    return openat(fd, p, flags);
}

int k3sm_stat(const char *path, struct stat *st) {
    char buf[K3SM_MAXPATH];
    return stat(k3sm_rebase(path, buf), st);
}

int k3sm_lstat(const char *path, struct stat *st) {
    char buf[K3SM_MAXPATH];
    return lstat(k3sm_rebase(path, buf), st);
}

int k3sm_fstatat(int fd, const char *path, struct stat *st, int flag) {
    char buf[K3SM_MAXPATH];
    const char *p = (path != NULL && path[0] == '/') ? k3sm_rebase(path, buf) : path;
    return fstatat(fd, p, st, flag);
}

int k3sm_access(const char *path, int mode) {
    char buf[K3SM_MAXPATH];
    return access(k3sm_rebase(path, buf), mode);
}

int k3sm_faccessat(int fd, const char *path, int mode, int flag) {
    char buf[K3SM_MAXPATH];
    const char *p = (path != NULL && path[0] == '/') ? k3sm_rebase(path, buf) : path;
    return faccessat(fd, p, mode, flag);
}

DIR *k3sm_opendir(const char *path) {
    char buf[K3SM_MAXPATH];
    return opendir(k3sm_rebase(path, buf));
}

__attribute__((used)) static const interpose_t k3sm_path_interposers[]
    __attribute__((section("__DATA,__interpose"))) = {
        {(const void *)k3sm_open, (const void *)open},
        {(const void *)k3sm_openat, (const void *)openat},
        {(const void *)k3sm_stat, (const void *)stat},
        {(const void *)k3sm_lstat, (const void *)lstat},
        {(const void *)k3sm_fstatat, (const void *)fstatat},
        {(const void *)k3sm_access, (const void *)access},
        {(const void *)k3sm_faccessat, (const void *)faccessat},
        {(const void *)k3sm_opendir, (const void *)opendir},
};
