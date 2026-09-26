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
 *
 * Shadow-shell exec rewrite (a second, independent job, configured by
 *   K3SM_SHADOW_DIR   - the node's directory of ad-hoc re-signed shell copies
 * and read ONCE, by a load-time constructor). dyld scrubs DYLD_* from the
 * environment of a restricted (platform / CS_RESTRICT) process, so a pod whose
 * process tree execs /bin/sh, /bin/bash, /bin/zsh, /bin/dash or /usr/bin/env
 * loses this shim and the DNS shim for that process and every descendant. The
 * node installer makes re-signed copies of those binaries (never of the /bin/sh
 * dispatcher, which re-execs /private/var/select/sh; bash serves as sh, entering
 * POSIX mode because argv[0]'s basename is "sh"), and this shim interposes
 * execve and posix_spawn to exec the copy instead. Those two public symbols are
 * the whole surface: posix_spawnp, the execvp/execl/execv/execvP family,
 * system(3) and popen(3) all reach them through a cross-image call on this
 * macOS (verified 2026-09-26, macOS 26: an interposer on just these two logged
 * every one of those entry points), so interposing the wrappers too would only
 * rewrite twice.
 *
 * It also parses shebangs itself: the kernel's own "#!" follow (imgact_shell)
 * happens inside execve, where no interposer can see it, so a direct exec of
 * ./entrypoint.sh would otherwise land on the platform interpreter. The target's
 * first line is read here and, when its interpreter is one of the five, the
 * kernel's argv shape is rebuilt (interp [one arg] script args...) and the copy
 * is exec'd. Recursion is bounded to that one level (the copy is a Mach-O, never
 * a script). TOCTOU: the file can change between this read and the exec; the
 * cost is the pre-shim behaviour for that one exec (the kernel follows whatever
 * shebang it finds), never a wider grant, because the rewrite only ever
 * substitutes a node-owned copy of a binary the pod could already run.
 *
 * The exec target (and a shebang's interpreter, and the file the shebang
 * probe reads) is rebased under the mount prefixes exactly as open() is, so a
 * container exec'ing a path under one of its mounts runs the materialized
 * copy, not the host path; the shadow plan is applied to the rebased target.
 *
 * When K3SM_SHADOW_DIR is unset or not absolute, or the directory or the copy
 * is not root-owned, of the right type (no symlink) and free of group/other
 * write bits, no shadow rewrite happens (the rebase still does).
 *
 * Everything on the exec path is async-signal-safe (stack buffers,
 * open/fstat/read/close/lstat, no malloc; the rebase config is parsed at load),
 * because execve is routinely called in a forked child of a multithreaded
 * process.
 */

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <spawn.h>
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

/* -------- exec: mount rebase + shadow-shell rewrite -------- */

#define K3SM_SHEBANG_MAX 512 /* the kernel's IMG_SHSIZE: what it reads of "#!" */

/*
 * K3SM_MAX_REWRITE_ARGC bounds the argv a rewrite copies onto the stack. The
 * copy is a VLA of argc + 3 pointers, sized only when a rewrite needs a new
 * vector; above this bound the exec falls through with no argv rewrite (the
 * target path is still rebased), because execve runs on arbitrary threads,
 * some with small stacks, and 4096 pointers (32 KiB) is the most this shim
 * will ever put there. A shell with more than 4096 arguments keeps its
 * pre-shim behaviour; it never overflows a stack.
 */
#define K3SM_MAX_REWRITE_ARGC 4096

static char g_shadow_dir[K3SM_MAXPATH];
static size_t g_shadow_dir_len;

/* The five host paths the copies stand in for, and the copy each maps to.
 * Pinned against the Go shadowCopies map by pkg/runtime
 * TestShadowMapMatchesInterposer: keep one entry per line in this shape. */
static const struct {
    const char *host;
    const char *copy;
} k3sm_shadow_map[] = {
    {"/bin/sh", "bash"},
    {"/bin/bash", "bash"},
    {"/bin/zsh", "zsh"},
    {"/bin/dash", "dash"},
    {"/usr/bin/env", "env"},
};

__attribute__((constructor)) static void k3sm_shadow_init(void) {
    /* Settle the rebase config at load too, so an exec in a forked child
     * never runs the (non-async-signal-safe) parse. */
    pthread_once(&g_once, k3sm_pathcfg_init);
    const char *d = getenv("K3SM_SHADOW_DIR");
    if (d == NULL || d[0] != '/') {
        return;
    }
    size_t l = strlen(d);
    while (l > 1 && d[l - 1] == '/') {
        l--;
    }
    if (l + 16 >= sizeof(g_shadow_dir)) {
        return; /* too long to hold "<dir>/<copy>": leave the feature off */
    }
    memcpy(g_shadow_dir, d, l);
    g_shadow_dir[l] = '\0';
    g_shadow_dir_len = l;
}

/*
 * k3sm_trusted reports whether path is owned by root, is a directory (want_dir)
 * or a regular file, is not a symlink (lstat), and carries no group or other
 * write bit. The shadow exec is exempt from the runtime's signature gate and
 * Seatbelt lets a pod read and exec under /Library, so ownership and mode are
 * the whole boundary: they are checked here, at the point of use.
 */
static int k3sm_trusted(const char *path, int want_dir) {
    struct stat st;
    if (lstat(path, &st) != 0 || st.st_uid != 0) {
        return 0;
    }
    if (want_dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) {
        return 0;
    }
    return (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

/*
 * k3sm_shadow_copy writes "<dir>/<copy>" into buf when host is one of the five
 * and both the directory and the copy pass k3sm_trusted, returning 1 and
 * setting *is_sh when host is /bin/sh; else returns 0 (the caller then runs
 * the real function on the original path).
 */
static int k3sm_shadow_copy(const char *host, char *buf, int *is_sh) {
    if (g_shadow_dir_len == 0 || host == NULL) {
        return 0;
    }
    for (size_t i = 0; i < sizeof(k3sm_shadow_map) / sizeof(k3sm_shadow_map[0]); i++) {
        if (strcmp(host, k3sm_shadow_map[i].host) != 0) {
            continue;
        }
        memcpy(buf, g_shadow_dir, g_shadow_dir_len);
        buf[g_shadow_dir_len] = '/';
        strcpy(buf + g_shadow_dir_len + 1, k3sm_shadow_map[i].copy);
        if (!k3sm_trusted(g_shadow_dir, 1) || !k3sm_trusted(buf, 0)) {
            return 0;
        }
        *is_sh = strcmp(host, "/bin/sh") == 0;
        return 1;
    }
    return 0;
}

/* k3sm_basename_is_sh reports whether s's last path component is "sh". */
static int k3sm_basename_is_sh(const char *s) {
    if (s == NULL) {
        return 0;
    }
    const char *b = strrchr(s, '/');
    return strcmp(b ? b + 1 : s, "sh") == 0;
}

/*
 * k3sm_shebang reads path's first line and, when it is "#!interp [arg]", copies
 * interp and the (optional, whitespace-trimmed, single) arg into the caller's
 * buffers and returns 1. Mirrors XNU's imgact_shell: everything after the
 * interpreter up to the newline is ONE argument. The open is O_NONBLOCK and
 * only a regular file is read, so a FIFO or a device never blocks the exec.
 */
static int k3sm_shebang(const char *path, char *interp, char *arg) {
    char head[K3SM_SHEBANG_MAX + 1];
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return 0;
    }
    ssize_t n = read(fd, head, K3SM_SHEBANG_MAX);
    close(fd);
    if (n < 3 || head[0] != '#' || head[1] != '!') {
        return 0;
    }
    head[n] = '\0';
    char *p = head + 2;
    char *end = memchr(p, '\n', (size_t)(n - 2));
    if (end == NULL) {
        return 0; /* no complete first line inside the kernel's window */
    }
    *end = '\0';
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    char *q = p;
    while (*q != '\0' && *q != ' ' && *q != '\t') {
        q++;
    }
    if (q == p || (size_t)(q - p) >= K3SM_MAXPATH) {
        return 0;
    }
    memcpy(interp, p, (size_t)(q - p));
    interp[q - p] = '\0';
    while (*q == ' ' || *q == '\t') {
        q++;
    }
    char *e = q + strlen(q);
    while (e > q && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) {
        e--;
    }
    memcpy(arg, q, (size_t)(e - q));
    arg[e - q] = '\0';
    return 1;
}

/* What an exec becomes. */
enum { K3SM_EXEC_ASIS, K3SM_EXEC_PATH, K3SM_EXEC_DIRECT, K3SM_EXEC_SCRIPT };

typedef struct {
    int kind;
    const char *exec_path;  /* the file to exec (all kinds but ASIS) */
    const char *argv0;      /* DIRECT: the new argv[0], or NULL to keep it */
    const char *interp_name; /* SCRIPT: argv[0] (the interpreter as written) */
    const char *script;     /* SCRIPT: the (rebased) script path */
    char path_buf[K3SM_MAXPATH];
    char copy_buf[K3SM_MAXPATH];
    char interp[K3SM_MAXPATH];
    char interp_buf[K3SM_MAXPATH];
    char arg[K3SM_SHEBANG_MAX + 1];
} k3sm_exec_plan_t;

/*
 * k3sm_plan_exec decides what an exec of path becomes, WITHOUT building any
 * argv. Order, identical to pkg/runtime shadowRewrite:
 *   1. the target is rebased exactly as k3sm_open rebases (a path under a
 *      mount prefix becomes "<rootfs><path>");
 *   2. the rebased target is one of the five and the copy is trusted: DIRECT;
 *   3. may_read_script and the rebased target is a script: its interpreter is
 *      rebased too; if the (unrebased) interpreter is one of the five and the
 *      copy is trusted, exec the copy; else if the rebase moved the
 *      interpreter, exec the rebased interpreter; either as SCRIPT, with the
 *      kernel's argv shape and the rebased script path;
 *   4. otherwise the rebased target, if the rebase moved it (PATH), else ASIS.
 * too_many_args (argc > K3SM_MAX_REWRITE_ARGC) limits the plan to PATH.
 */
static void k3sm_plan_exec(const char *path, char *const argv[], int may_read_script,
                           int too_many_args, k3sm_exec_plan_t *pl) {
    pl->kind = K3SM_EXEC_ASIS;
    if (path == NULL) {
        return;
    }
    const char *target = k3sm_rebase(path, pl->path_buf);
    int moved = target != path;
    int is_sh = 0;
    if (!too_many_args && argv != NULL) {
        if (k3sm_shadow_copy(target, pl->copy_buf, &is_sh)) {
            pl->kind = K3SM_EXEC_DIRECT;
            pl->exec_path = pl->copy_buf;
            pl->argv0 = NULL;
            if (is_sh && (argv[0] == NULL || !k3sm_basename_is_sh(argv[0]))) {
                pl->argv0 = "sh"; /* bash enters POSIX mode only when named sh */
            }
            return;
        }
        if (may_read_script && (g_shadow_dir_len != 0 || g_cfg.enabled) &&
            k3sm_shebang(target, pl->interp, pl->arg)) {
            const char *ri = k3sm_rebase(pl->interp, pl->interp_buf);
            if (k3sm_shadow_copy(pl->interp, pl->copy_buf, &is_sh)) {
                pl->kind = K3SM_EXEC_SCRIPT;
                pl->exec_path = pl->copy_buf;
                pl->interp_name = is_sh && !k3sm_basename_is_sh(pl->interp) ? "sh" : pl->interp;
                pl->script = target;
                return;
            }
            if (ri != pl->interp) {
                pl->kind = K3SM_EXEC_SCRIPT;
                pl->exec_path = ri;
                pl->interp_name = pl->interp;
                pl->script = target;
                return;
            }
        }
    }
    if (moved) {
        pl->kind = K3SM_EXEC_PATH;
        pl->exec_path = target;
    }
}

/* k3sm_argc counts argv, stopping one past the rewrite bound. */
static size_t k3sm_argc(char *const argv[]) {
    size_t argc = 0;
    if (argv != NULL) {
        while (argv[argc] != NULL && argc <= K3SM_MAX_REWRITE_ARGC) {
            argc++;
        }
    }
    return argc;
}

/* k3sm_fill_argv writes the rewritten vector for a DIRECT or SCRIPT plan into
 * nargv (capacity argc + 3, the caller's VLA). */
static void k3sm_fill_argv(const k3sm_exec_plan_t *pl, char *const argv[], size_t argc, char **nargv) {
    size_t j = 0;
    if (pl->kind == K3SM_EXEC_DIRECT) {
        for (size_t i = 0; i < argc; i++) {
            nargv[j++] = argv[i];
        }
        if (pl->argv0 != NULL) {
            if (j == 0) {
                j = 1;
            }
            nargv[0] = (char *)pl->argv0;
        }
        nargv[j] = NULL;
        return;
    }
    /* SCRIPT: interp [arg] script argv[1..] */
    nargv[j++] = (char *)pl->interp_name;
    if (pl->arg[0] != '\0') {
        nargv[j++] = (char *)pl->arg;
    }
    nargv[j++] = (char *)pl->script;
    for (size_t i = 1; i < argc; i++) {
        nargv[j++] = argv[i];
    }
    nargv[j] = NULL;
}

int k3sm_execve(const char *path, char *const argv[], char *const envp[]) {
    if (g_shadow_dir_len == 0 && !g_cfg.enabled) {
        return execve(path, argv, envp);
    }
    size_t argc = k3sm_argc(argv);
    k3sm_exec_plan_t pl;
    /* execve resolves a relative path against the caller's own cwd, which is
     * also where the shebang read resolves it. */
    k3sm_plan_exec(path, argv, 1, argc > K3SM_MAX_REWRITE_ARGC, &pl);
    switch (pl.kind) {
    case K3SM_EXEC_PATH:
        return execve(pl.exec_path, argv, envp);
    case K3SM_EXEC_DIRECT:
    case K3SM_EXEC_SCRIPT: {
        char *nargv[argc + 3]; /* sized only now, argc <= K3SM_MAX_REWRITE_ARGC */
        k3sm_fill_argv(&pl, argv, argc, nargv);
        return execve(pl.exec_path, nargv, envp);
    }
    default:
        return execve(path, argv, envp);
    }
}

int k3sm_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa,
                     const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
    if (g_shadow_dir_len == 0 && !g_cfg.enabled) {
        return posix_spawn(pid, path, fa, attr, argv, envp);
    }
    size_t argc = k3sm_argc(argv);
    k3sm_exec_plan_t pl;
    /* A file action may chdir the child before the kernel resolves a relative
     * path, and the actions are opaque here, so a relative script is not read. */
    int may_read = path != NULL && (path[0] == '/' || fa == NULL);
    k3sm_plan_exec(path, argv, may_read, argc > K3SM_MAX_REWRITE_ARGC, &pl);
    switch (pl.kind) {
    case K3SM_EXEC_PATH:
        return posix_spawn(pid, pl.exec_path, fa, attr, argv, envp);
    case K3SM_EXEC_DIRECT:
    case K3SM_EXEC_SCRIPT: {
        char *nargv[argc + 3]; /* sized only now, argc <= K3SM_MAX_REWRITE_ARGC */
        k3sm_fill_argv(&pl, argv, argc, nargv);
        return posix_spawn(pid, pl.exec_path, fa, attr, nargv, envp);
    }
    default:
        return posix_spawn(pid, path, fa, attr, argv, envp);
    }
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
        {(const void *)k3sm_execve, (const void *)execve},
        {(const void *)k3sm_posix_spawn, (const void *)posix_spawn},
};
