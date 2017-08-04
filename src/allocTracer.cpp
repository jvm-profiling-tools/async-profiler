/*
 * Copyright 2017 Andrei Pangin
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

#include <fstream>
#include <stdint.h>
#include <ucontext.h>
#include <sys/mman.h>
#include "allocTracer.h"
#include "codeCache.h"
#include "profiler.h"
#include "stackFrame.h"


Trap AllocTracer::_in_new_tlab("_ZN11AllocTracer33send_allocation_in_new_tlab_eventE11KlassHandlemm");
Trap AllocTracer::_outside_tlab("_ZN11AllocTracer34send_allocation_outside_tlab_eventE11KlassHandlem");


// Make the entry point writeable and insert breakpoint at the very first instruction
void Trap::install() {
    uintptr_t page_start = (uintptr_t)_entry & ~0xfffULL;
    mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

    _saved_insn = *_entry;
    *_entry = BREAKPOINT;
    flushCache(_entry);
}

// Clear breakpoint - restore the original instruction
void Trap::uninstall() {
    *_entry = _saved_insn;
    flushCache(_entry);
}


void AllocTracer::inNewTLAB(VMKlass* alloc_class, unsigned long tlab_size, unsigned long obj_size) {
    ucontext_t ucontext;
    getcontext(&ucontext);
    Profiler::_instance.recordSample(&ucontext, obj_size, alloc_class);
}

void AllocTracer::outsideTLAB(VMKlass* alloc_class, unsigned long obj_size) {
    ucontext_t ucontext;
    getcontext(&ucontext);
    Profiler::_instance.recordSample(&ucontext, obj_size, alloc_class);
}

bool AllocTracer::checkTracerSymbols() {
    if (_in_new_tlab._entry == NULL || _outside_tlab._entry == NULL) {
        NativeCodeCache* libjvm = Profiler::_instance.jvmLibrary();
        if (libjvm != NULL) {
            _in_new_tlab._entry = (instruction_t*)libjvm->findSymbol(_in_new_tlab._func_name);
            _outside_tlab._entry = (instruction_t*)libjvm->findSymbol(_outside_tlab._func_name);
        }
    }
    return _in_new_tlab._entry != NULL && _outside_tlab._entry != NULL;
}

void AllocTracer::installSignalHandler() {
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = NULL;
    sa.sa_sigaction = signalHandler;
    sa.sa_flags = SA_RESTART | SA_SIGINFO;

    sigaction(SIGTRAP, &sa, NULL);
}

void AllocTracer::signalHandler(int signo, siginfo_t* siginfo, void* ucontext) {
    uintptr_t& pc = StackFrame::pc((ucontext_t*)ucontext);

    if (pc == (uintptr_t)(_in_new_tlab._entry + 1)) {
        pc = (uintptr_t)inNewTLAB;
    } else if (pc == (uintptr_t)(_outside_tlab._entry + 1)) {
        pc = (uintptr_t)outsideTLAB;
    }
}

bool AllocTracer::start() {
    if (!VMStructs::available()) {
        std::cerr << "VMStructs unavailable. Unsupported JVM?" << std::endl;
        return false;
    }

    if (!checkTracerSymbols()) {
        std::cerr << "No AllocTracer symbols found. Are JDK debug symbols installed?" << std::endl;
        return false;
    }

    installSignalHandler();

    _in_new_tlab.install();
    _outside_tlab.install();

    return true;
}

void AllocTracer::stop() {
    _in_new_tlab.uninstall();
    _outside_tlab.uninstall();
}
