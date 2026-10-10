/* DRAFT larger build boundary: the proven tiny control is included unchanged.
 * This new root/exec policy has NOT been compiled or qualified on Linux.
 * Read roots and executable/environment are validated by the reviewed parent;
 * this boundary independently bounds parsing, closes inherited descriptors,
 * then enforces Landlock and the identical network/io_uring seccomp policy.
 */
#define main tiny_control_main
#include "confinement-proof.c"
#undef main

static int beneath(const char *path, const char *root) {
    size_t n = strlen(root);
    return !strncmp(path, root, n) && (path[n] == '/' || path[n] == 0);
}

static void leaf_rule(int ruleset, const char *path, int executable) {
    struct stat info;
    if (lstat(path, &info) || S_ISLNK(info.st_mode)) fail("read-root-type");
    uint64_t rights = LANDLOCK_ACCESS_FS_READ_FILE;
    if (S_ISDIR(info.st_mode)) rights |= LANDLOCK_ACCESS_FS_READ_DIR;
    else if (!S_ISREG(info.st_mode)) fail("read-root-not-file-or-directory");
    if (executable) rights |= LANDLOCK_ACCESS_FS_EXECUTE;
    rule(ruleset, path, rights);
}

int main(int argc, char **argv) {
    /* work, read-roots, environment, cargo, immutable source, operation, SHA. */
    if (argc != 8) return 64;
    const char *work = argv[1], *roots_path = argv[2], *env_path = argv[3], *cargo = argv[4];
    if (strcmp(argv[6], "test-compile") && strcmp(argv[6], "test")) return 64;
    if (strlen(argv[7]) != 40 || strspn(argv[7], "0123456789abcdef") != 40) return 64;
    if (argv[5][0] != '/' || strlen(argv[5]) > 1024 || strstr(argv[5], "..")) return 64;
    char manifest[1100];
    if (snprintf(manifest, sizeof(manifest), "%s/Cargo.toml", argv[5]) >= (int)sizeof(manifest)) return 64;
    if (strlen(work) > 1024 || strlen(roots_path) > 1024 || strlen(cargo) > 1024 || strlen(env_path) > 1024 ||
        work[0] != '/' || roots_path[0] != '/' || cargo[0] != '/' || env_path[0] != '/') return 64;
    if (strstr(work, "..") || strstr(roots_path, "..") || strstr(cargo, "..")) return 64;
    struct stat work_info;
    if (lstat(work, &work_info) || !S_ISDIR(work_info.st_mode) ||
        work_info.st_uid != getuid() || (work_info.st_mode & 077)) return 64;
    /* This descriptor is policy data, never an inherited FD. */
    int roots = open(roots_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat roots_info;
    if (roots < 0 || fstat(roots, &roots_info) || !S_ISREG(roots_info.st_mode) ||
        roots_info.st_size > 32768 || roots_info.st_uid != getuid() || roots_info.st_nlink != 1 ||
        (roots_info.st_mode & 022)) fail("read-roots-manifest");
    FILE *input = fdopen(roots, "r");
    if (!input) fail("read-roots-stream");
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 3) fail("landlock-abi3-required");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail("no-new-privs");
    uint64_t read_rights = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    uint64_t writable = read_rights | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;
    /* MAKE_SYM is needed for ordinary Cargo/RocksDB build artifacts inside the
     * private work root only; no host symlink mutation grant is added. */
    struct landlock_ruleset_attr policy = { .handled_access_fs = writable |
        LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO };
    int ruleset = syscall(SYS_landlock_create_ruleset, &policy, sizeof(policy), 0);
    if (ruleset < 0) fail("landlock-create");
    rule(ruleset, work, writable);
    char line[1028];
    int count = 0, cargo_allowed = 0, source_allowed = 0;
    while (fgets(line, sizeof(line), input)) {
        size_t n = strlen(line);
        if (++count > 128 || n < 4 || n >= sizeof(line) - 1 || line[n - 1] != '\n' ||
            (line[0] != 'R' && line[0] != 'X') || line[1] != ' ' || line[2] != '/')
            fail("read-root-line-bound");
        line[n - 1] = 0;
        const char *path = line + 2;
        if (strstr(path, "..") || !strcmp(path, "/") ||
            !strcmp(path, "/home") || !strcmp(path, "/usr") || !strcmp(path, "/proc") ||
            !strcmp(path, "/etc") || beneath(path, work)) fail("overbroad-read-root");
        leaf_rule(ruleset, path, line[0] == 'X');
        if (line[0] == 'X' && !strcmp(path, cargo)) cargo_allowed = 1;
        if (line[0] == 'R' && !strcmp(path, argv[5])) source_allowed = 1;
    }
    if (ferror(input) || !cargo_allowed || !source_allowed) fail("read-root-read-or-cargo-source");
    fclose(input);
    int env_fd = open(env_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat env_info;
    if (env_fd < 0 || fstat(env_fd, &env_info) || !S_ISREG(env_info.st_mode) || env_info.st_nlink != 1 ||
        env_info.st_uid != getuid() || (env_info.st_mode & 077) || env_info.st_size > 16384)
        fail("explicit-environment-manifest");
    FILE *env_input = fdopen(env_fd, "r");
    if (!env_input || clearenv() || setenv("LANG", "C", 1)) fail("clean-environment");
    const char *allowed[] = { "PATH", "CARGO_HOME", "CARGO_TARGET_DIR", "TMPDIR", "RUSTC",
        "CC", "CXX", "AR", "LIBCLANG_PATH", "LD_LIBRARY_PATH", "HOME", NULL };
    unsigned seen = 0;
    while (fgets(line, sizeof(line), env_input)) {
        size_t n = strlen(line);
        if (n < 4 || n >= sizeof(line) - 1 || line[n - 1] != '\n') fail("environment-line-bound");
        line[n - 1] = 0;
        char *equal = strchr(line, '=');
        if (!equal || equal[1] != '/' || strstr(equal + 1, "..")) fail("environment-value");
        *equal = 0;
        int key = -1;
        for (int i = 0; allowed[i]; ++i) if (!strcmp(line, allowed[i])) key = i;
        if (key < 0 || (seen & (1U << key))) fail("environment-key-duplicate-or-unreviewed");
        seen |= 1U << key;
        if (setenv(line, equal + 1, 1)) fail("explicit-environment");
    }
    if (ferror(env_input) || seen != ((1U << 11) - 1)) fail("environment-required-key");
    fclose(env_input);
    if (!beneath(getenv("CARGO_HOME"), work) || !beneath(getenv("CARGO_TARGET_DIR"), work) ||
        !beneath(getenv("TMPDIR"), work) || !beneath(getenv("HOME"), work) ||
        !beneath(getenv("PATH"), work)) fail("private-environment-roots");
    if (setenv("GIT_HASH", argv[7], 1) || setenv("ELECTRS_SOURCE_REVISION", argv[7], 1)) fail("full-source-stamp");
    if (chdir(work)) fail("private-cwd");
    int in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int out = open("cargo.stdout", O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    int err = open("cargo.stderr", O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    if (in < 0 || out < 0 || err < 0 || dup2(in, 0) < 0 || dup2(out, 1) < 0 || dup2(err, 2) < 0)
        fail("owned-stdio");
    if (syscall(SYS_landlock_restrict_self, ruleset, 0)) fail("landlock-enforce");
    if (syscall(SYS_close_range, 3U, ~0U, CLOSE_RANGE_UNSHARE)) fail("close-range-unshare");
    restrict_syscalls();
    no_network_tests();
    char *args[] = { (char *)cargo, "test", "--offline", "--frozen", "--jobs", "2",
        "--manifest-path", manifest, NULL, NULL };
    if (!strcmp(argv[6], "test-compile")) args[8] = "--no-run";
    execv(cargo, args);
    fail("direct-cargo-exec");
    return 70;
}
