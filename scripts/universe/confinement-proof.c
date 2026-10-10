/* Source-only proof bootstrap. No build/native action until root review.
 * Existing kernel headers/libc only; no libseccomp/package dependency.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/close_range.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__x86_64__) || defined(__ILP32__)
#error "This reviewed proof supports Linux x86_64 only"
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#error "Existing headers lack required Landlock ABI3 rights; no fallback"
#endif

static void fail(const char *step) {
    fprintf(stderr, "confinement-proof:%s errno=%d\n", step, errno);
    exit(70);
}

static int denied(long result) { return result == -1 && errno == EPERM; }

static void no_network_tests(void) {
    errno = 0;
    if (!denied(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0))) fail("inet-socket-not-denied");
    errno = 0;
    if (!denied(syscall(SYS_socket, AF_INET6, SOCK_DGRAM, 0))) fail("inet6-socket-not-denied");
    errno = 0;
    if (!denied(syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0))) fail("unix-socket-not-denied");
    /* Invalid fds ensure no actual address/Core connection is attempted. EPERM,
     * not EBADF, proves the filter denied before the networking implementation.
     */
    errno = 0;
    if (!denied(syscall(SYS_connect, -1, NULL, 0))) fail("connect-not-denied");
    errno = 0;
    if (!denied(syscall(SYS_sendmsg, -1, NULL, 0))) fail("sendmsg-not-denied");
    errno = 0;
    if (!denied(syscall(SYS_io_uring_setup, 0, NULL))) fail("uring-setup-not-denied");
    errno = 0;
    if (!denied(syscall(SYS_io_uring_enter, -1, 0, 0, 0, NULL, 0))) fail("uring-enter-not-denied");
    errno = 0;
    if (!denied(syscall(SYS_io_uring_register, -1, 0, NULL, 0))) fail("uring-register-not-denied");
    if (prctl(PR_GET_SECCOMP) != SECCOMP_MODE_FILTER || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        fail("filter-inheritance-not-observed");
}

static void fs_tests(const char *readonly, const char *private_path) {
    int fd = open(readonly, O_WRONLY | O_TRUNC | O_NOFOLLOW);
    if (fd >= 0) { close(fd); errno = 0; fail("outside-write-was-allowed"); }
    if (errno != EACCES && errno != EPERM) fail("outside-write-not-policy-denial");
    char path[4096];
    int size = snprintf(path, sizeof(path), "%s/probe-file-%ld", private_path, (long)getpid());
    if (size < 0 || size >= (int)sizeof(path)) fail("private-path-bound");
    fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0600);
    if (fd < 0 || write(fd, "owned", 5) != 5 || ftruncate(fd, 3)) fail("private-write-not-allowed");
    close(fd);
    if (unlink(path)) fail("private-cleanup-not-allowed");
}

#define DENY(nr) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
static void restrict_syscalls(void) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        DENY(SYS_socket), DENY(SYS_socketpair), DENY(SYS_connect), DENY(SYS_bind),
        DENY(SYS_listen), DENY(SYS_accept), DENY(SYS_accept4), DENY(SYS_sendto),
        DENY(SYS_getsockname), DENY(SYS_getpeername), DENY(SYS_setsockopt), DENY(SYS_getsockopt),
        DENY(SYS_sendmsg), DENY(SYS_sendmmsg), DENY(SYS_recvfrom), DENY(SYS_recvmsg),
        DENY(SYS_recvmmsg), DENY(SYS_shutdown), DENY(SYS_io_uring_setup),
        DENY(SYS_io_uring_enter), DENY(SYS_io_uring_register), DENY(SYS_pidfd_getfd),
        DENY(SYS_pidfd_open), DENY(SYS_pidfd_send_signal),
        DENY(SYS_ptrace), DENY(SYS_process_vm_readv), DENY(SYS_process_vm_writev),
        DENY(SYS_bpf), DENY(SYS_unshare), DENY(SYS_setns), DENY(SYS_mount),
        DENY(SYS_umount2), DENY(SYS_ioctl), DENY(SYS_kill), DENY(SYS_tkill), DENY(SYS_tgkill),
        DENY(SYS_rt_sigqueueinfo), DENY(SYS_rt_tgsigqueueinfo),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = { .len = sizeof(code) / sizeof(code[0]), .filter = code };
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program)) fail("seccomp-install");
}

static void rule(int ruleset, const char *path, uint64_t rights) {
    int fd = open(path, O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("landlock-path-open");
    struct landlock_path_beneath_attr entry = { .allowed_access = rights, .parent_fd = fd };
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &entry, 0)) fail("landlock-rule");
    close(fd);
}

int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "--inherited")) {
        no_network_tests();
        fs_tests(argv[2], argv[3]);
        return 0;
    }
    if (argc != 3 || argv[1][0] != '/' || argv[2][0] != '/') return 64;
    const char *private_path = argv[1], *readonly = argv[2];
    if (strlen(private_path) > 1024 || strlen(readonly) > 1024) return 64;
    if (!strncmp(readonly, private_path, strlen(private_path))) return 64;
    if (clearenv() || setenv("LANG", "C", 1)) fail("clean-environment");
    char self[4096];
    ssize_t len = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (len <= 0 || len >= (ssize_t)sizeof(self) - 1) fail("self-executable-path");
    self[len] = 0;
    if (strncmp(self, private_path, strlen(private_path)) || self[strlen(private_path)] != '/')
        fail("executable-outside-private-root");
    if (chdir(private_path)) fail("private-cwd");
    /* Replace inherited pipe/socket stdio with new owned regular files before
     * closing all remaining descriptors and applying policy.
     */
    int in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int out = open("proof.stdout", O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    int err = open("proof.stderr", O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    if (in < 0 || out < 0 || err < 0 || dup2(in, 0) < 0 || dup2(out, 1) < 0 || dup2(err, 2) < 0)
        fail("owned-stdio");
    int sentinel = open(readonly, O_RDONLY | O_NOFOLLOW);
    if (sentinel < 0 || dup2(sentinel, 100) < 0) fail("descriptor-control");
    if (syscall(SYS_close_range, 3U, ~0U, CLOSE_RANGE_UNSHARE)) fail("close-range-unshare");
    struct stat info;
    if (fstat(100, &info) == 0 || errno != EBADF || fstat(1, &info) || !S_ISREG(info.st_mode))
        fail("inherited-descriptor-not-closed");
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 3) fail("landlock-abi3-required");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail("no-new-privs");
    uint64_t read_rights = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    uint64_t writable = read_rights | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;
    struct landlock_ruleset_attr policy = { .handled_access_fs = writable |
        LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_SYM };
    int ruleset = syscall(SYS_landlock_create_ruleset, &policy, sizeof(policy), 0);
    if (ruleset < 0) fail("landlock-create");
    rule(ruleset, private_path, writable);
    /* Static ELF needs no broad home/tool/library roots. A later build wrapper
     * must add individually reviewed read/execute leaves, never a home grant.
     */
    if (syscall(SYS_landlock_restrict_self, ruleset, 0)) fail("landlock-enforce");
    close(ruleset);
    restrict_syscalls();
    no_network_tests();
    fs_tests(readonly, private_path);
    pid_t pid = fork();
    if (pid < 0) fail("inheritance-fork");
    if (pid == 0) {
        char *clean[] = { "PATH=/usr/bin:/bin", "LANG=C", NULL };
        char *args[] = { self, "--inherited", (char *)readonly, (char *)private_path, NULL };
        execve(self, args, clean);
        _exit(71);
    }
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) fail("inheritance-exec");
    printf("{\"landlockAbi\":%d,\"seccompEnforced\":true,\"outsideWriteDenied\":true,\"privateWriteAllowed\":true,\"allNetworkAndUringDenied\":true,\"inheritedFdsClosed\":true,\"forkExecPolicyInherited\":true,\"coreConnectionAttempted\":false,\"fullBuildQualified\":false}\n", abi);
    fflush(stdout);
    /* Keep scope alive briefly for actual parent resource-property observation.
     * No network or daemon polling; only this owned local release marker.
     */
    for (int tries = 0; tries < 400; ++tries) {
        int release = open("release", O_RDONLY | O_NOFOLLOW);
        if (release >= 0) { close(release); return 0; }
        if (errno != ENOENT) fail("parent-release-policy");
        usleep(20000);
    }
    fail("parent-resource-proof-timeout");
    return 0;
}
