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

#ifndef _UTILS_H
#define _UTILS_H

#if defined(__APPLE__)

#include <sys/sysctl.h>

#else // __FreeBSD__

#include <sys/sysctl.h>
#include <sys/user.h>

#endif

#define MAX_PATH 1024
#define TMP_PATH (MAX_PATH - 64)

extern char tmp_path[TMP_PATH];

int get_process_info(int pid, uid_t* uid, gid_t* gid, int* nspid, int *tgid);
int get_tmp_path(int pid);
int enter_ns(int pid, const char *type);
int alt_lookup_nspid(int pid);

#endif
