/*
 * Copyright 2016 Andrei Pangin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "utils.h"

char tmp_path[TMP_PATH];

#ifdef __linux__

int get_process_info(int pid, uid_t* uid, gid_t* gid, int* nspid) {
    // Parse /proc/pid/status to find process credentials
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE* status_file = fopen(path, "r");
    if (status_file == NULL) {
        return 0;
    }

    char* line = NULL;
    size_t size;

    while (getline(&line, &size, status_file) != -1) {
        if (strncmp(line, "Uid:", 4) == 0) {
            // Get the effective UID, which is the second value in the line
            *uid = (uid_t)atoi(strchr(line + 5, '\t'));
        } else if (strncmp(line, "Gid:", 4) == 0) {
            // Get the effective GID, which is the second value in the line
            *gid = (gid_t)atoi(strchr(line + 5, '\t'));
        } else if (strncmp(line, "NStgid:", 7) == 0) {
            // PID namespaces can be nested; the last one is the innermost one
            *nspid = atoi(strrchr(line, '\t'));
        }
    }

    free(line);
    fclose(status_file);
    return 1;
}

int get_tmp_path(int pid) {
    // A process may have its own root path (when running in chroot environment)
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/root", pid);

    // Append /tmp to the resolved root symlink
    ssize_t path_size = readlink(path, tmp_path, sizeof(tmp_path) - 10);
    strcpy(tmp_path + (path_size > 1 ? path_size : 0), "/tmp");
    return 1;
}

int enter_ns(int pid, const char *type) {
#ifdef __NR_setns
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, type);
    char selfpath[128];
    snprintf(selfpath, sizeof(selfpath), "/proc/self/ns/%s", type);

    struct stat oldns_stat, newns_stat;
    if (stat(selfpath, &oldns_stat) == 0 && stat(path, &newns_stat) == 0) {
        // Don't try to call setns() if we're in the same namespace already
        if (oldns_stat.st_ino != newns_stat.st_ino) {
            int newns = open(path, O_RDONLY);
            if (newns < 0) {
                return 0;
            }

            // Some ancient Linux distributions do not have setns() function
            int result = syscall(__NR_setns, newns, 0);
            close(newns);
            return result < 0 ? 0 : 1;
        }
    }
#endif // __NR_setns

    return 1;
}

// The first line of /proc/pid/sched looks like
// java (1234, #threads: 12)
// where 1234 is the required host PID
int sched_get_host_pid(const char* path) {
    static char* line = NULL;
    size_t size;
    int result = -1;

    FILE* sched_file = fopen(path, "r");
    if (sched_file != NULL) {
        if (getline(&line, &size, sched_file) != -1) {
            char* c = strrchr(line, '(');
            if (c != NULL) {
                result = atoi(c + 1);
            }
        }
        fclose(sched_file);
    }

    return result;
}

// Linux kernels < 4.1 do not export NStgid field in /proc/pid/status.
// Fortunately, /proc/pid/sched in a container exposes a host PID,
// so the idea is to scan all container PIDs to find which one matches the host PID.
int alt_lookup_nspid(int pid) {
    int namespace_differs = 0;
    char path[300];
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);

    // Don't bother looking for container PID if we are already in the same PID namespace
    struct stat oldns_stat, newns_stat;
    if (stat("/proc/self/ns/pid", &oldns_stat) == 0 && stat(path, &newns_stat) == 0) {
        if (oldns_stat.st_ino == newns_stat.st_ino) {
            return pid;
        }
        namespace_differs = 1;
    }

    // Otherwise browse all PIDs in the namespace of the target process
    // trying to find which one corresponds to the host PID
    snprintf(path, sizeof(path), "/proc/%d/root/proc", pid);
    DIR* dir = opendir(path);
    if (dir != NULL) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] >= '1' && entry->d_name[0] <= '9') {
                // Check if /proc/<container-pid>/sched points back to <host-pid>
                snprintf(path, sizeof(path), "/proc/%d/root/proc/%s/sched", pid, entry->d_name);
                if (sched_get_host_pid(path) == pid) {
                    closedir(dir);
                    return atoi(entry->d_name);
                }
            }
        }
        closedir(dir);
    }

    if (namespace_differs) {
        printf("WARNING: couldn't find container pid of the target process\n");
    }

    return pid;
}

#elif defined(__APPLE__)

int get_process_info(int pid, uid_t* uid, gid_t* gid, int* nspid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info;
    size_t len = sizeof(info);

    if (sysctl(mib, 4, &info, &len, NULL, 0) < 0 || len <= 0) {
        return 0;
    }

    *uid = info.kp_eproc.e_ucred.cr_uid;
    *gid = info.kp_eproc.e_ucred.cr_gid;
    *nspid = pid;
    return 1;
}

// macOS has a secure per-user temporary directory
int get_tmp_path(int pid) {
    int path_size = confstr(_CS_DARWIN_USER_TEMP_DIR, tmp_path, sizeof(tmp_path));
    return path_size > 0 && path_size <= sizeof(tmp_path);
}

// This is a Linux-specific API; nothing to do on macOS and FreeBSD
int enter_ns(int pid, const char *type) {
    return 1;
}

// Not used on macOS and FreeBSD
int alt_lookup_nspid(int pid) {
    return pid;
}

#else // __FreeBSD__

int get_process_info(int pid, uid_t* uid, gid_t* gid, int* nspid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info;
    size_t len = sizeof(info);

    if (sysctl(mib, 4, &info, &len, NULL, 0) < 0 || len <= 0) {
        return 0;
    }

    *uid = info.ki_uid;
    *gid = info.ki_groups[0];
    *nspid = pid;
    return 1;
}

// Use default /tmp path on FreeBSD
int get_tmp_path(int pid) {
    return 0;
}

// This is a Linux-specific API; nothing to do on macOS and FreeBSD
int enter_ns(int pid, const char *type) {
    return 1;
}

// Not used on macOS and FreeBSD
int alt_lookup_nspid(int pid) {
    return pid;
}

#endif
