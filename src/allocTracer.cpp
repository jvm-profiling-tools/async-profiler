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

#include <unistd.h>
#include <sys/mman.h>
#include "allocTracer.h"
#include "os.h"
#include "profiler.h"
#include "stackFrame.h"
#include "vmStructs.h"


// JDK 7-9
Trap AllocTracer::_in_new_tlab("_ZN11AllocTracer33send_allocation_in_new_tlab_event");
Trap AllocTracer::_outside_tlab("_ZN11AllocTracer34send_allocation_outside_tlab_event");
// JDK 10+
Trap AllocTracer::_in_new_tlab2("_ZN11AllocTracer27send_allocation_in_new_tlab");
Trap AllocTracer::_outside_tlab2("_ZN11AllocTracer28send_allocation_outside_tlab");
void (*AllocTracer::_next_handler)(int, siginfo_t *, void *) = 0;

u64 AllocTracer::_interval;
volatile u64 AllocTracer::_allocated_bytes;


// Resolve the address of the intercepted function
bool Trap::resolve(NativeCodeCache* libjvm) {
    if (_entry != NULL) {
        return true;
    }

    _entry = (instruction_t*)libjvm->findSymbolByPrefix(_func_name);
    if (_entry != NULL) {
        // Make the entry point writable, so we can rewrite instructions
        long page_size = sysconf(_SC_PAGESIZE);
        uintptr_t page_start = (uintptr_t)_entry & -page_size;
        mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
        return true;
    }

    return false;
}

// Insert breakpoint at the very first instruction
void Trap::install() {
    if (_entry != NULL) {
        _saved_insn = *(_entry + BREAKPOINT_OFFSET);
        *(_entry + BREAKPOINT_OFFSET) = BREAKPOINT;
        flushCache(_entry + BREAKPOINT_OFFSET);
    }
}

// Clear breakpoint - restore the original instruction
void Trap::uninstall() {
    if (_entry != NULL) {
        *(_entry + BREAKPOINT_OFFSET) = _saved_insn;
        flushCache(_entry + BREAKPOINT_OFFSET);
    }
}


// Called whenever our breakpoint trap is hit
void AllocTracer::signalHandler(int signo, siginfo_t* siginfo, void* ucontext) {
    StackFrame frame(ucontext);
    struct sigaction oact, nex;

    sigaction( signo, NULL, &oact);
    // PC points either to BREAKPOINT instruction or to the next one
    if (frame.pc() - (uintptr_t)(_in_new_tlab._entry + BREAKPOINT_OFFSET) <= sizeof(instruction_t)) {
        // send_allocation_in_new_tlab_event(KlassHandle klass, size_t tlab_size, size_t alloc_size)
        recordAllocation(ucontext, frame.arg0(), frame.arg1(), false);
    } else if (frame.pc() - (uintptr_t)(_outside_tlab._entry + BREAKPOINT_OFFSET) <= sizeof(instruction_t)) {
        // send_allocation_outside_tlab_event(KlassHandle klass, size_t alloc_size);
        recordAllocation(ucontext, frame.arg0(), frame.arg1(), true);
    } else if (frame.pc() - (uintptr_t)(_in_new_tlab2._entry + BREAKPOINT_OFFSET) <= sizeof(instruction_t)) {
        // send_allocation_in_new_tlab(Klass* klass, HeapWord* obj, size_t tlab_size, size_t alloc_size, Thread* thread)
        recordAllocation(ucontext, frame.arg0(), frame.arg2(), false);
    } else if (frame.pc() - (uintptr_t)(_outside_tlab2._entry + BREAKPOINT_OFFSET) <= sizeof(instruction_t)) {
        // send_allocation_outside_tlab(Klass* klass, HeapWord* obj, size_t alloc_size, Thread* thread)
        recordAllocation(ucontext, frame.arg0(), frame.arg2(), true);
    } else {
        // Not our trap, call the the VM's handler if there is one
        if ((void*)_next_handler != SIG_DFL && (void*)_next_handler != SIG_ERR && (void*)_next_handler != SIG_IGN && _next_handler != NULL ) {
            (*_next_handler)(signo, siginfo, ucontext);
        }
        return;
   }

    // Leave the trapped function by simulating "ret" instruction
    frame.ret();
}

void AllocTracer::recordAllocation(void* ucontext, uintptr_t rklass, uintptr_t rsize, bool outside_tlab) {
    if (_interval) {
        // Do not record allocation unless allocated at least _interval bytes
        while (true) {
            u64 prev = _allocated_bytes;
            u64 next = prev + rsize;
            if (next < _interval) {
                if (__sync_bool_compare_and_swap(&_allocated_bytes, prev, next)) {
                    return;
                }
            } else {
                if (__sync_bool_compare_and_swap(&_allocated_bytes, prev, next % _interval)) {
                    break;
                }
            }
        }
    }

    VMSymbol* symbol = VMKlass::fromHandle(rklass)->name();
    if (outside_tlab) {
        // Invert the last bit to distinguish jmethodID from the allocation in new TLAB
        Profiler::_instance.recordSample(ucontext, rsize, BCI_SYMBOL_OUTSIDE_TLAB, (jmethodID)((uintptr_t)symbol ^ 1));
    } else {
        Profiler::_instance.recordSample(ucontext, rsize, BCI_SYMBOL, (jmethodID)symbol);
    }
}

Error AllocTracer::start(Arguments& args) {
    if (!VMStructs::available()) {
        return Error("VMStructs unavailable. Unsupported JVM?");
    }

    NativeCodeCache* libjvm = Profiler::_instance.jvmLibrary();
    if (!(_in_new_tlab.resolve(libjvm) || _in_new_tlab2.resolve(libjvm)) ||
        !(_outside_tlab.resolve(libjvm) || _outside_tlab2.resolve(libjvm))) {
        return Error("No AllocTracer symbols found. Are JDK debug symbols installed?");
    }

    _interval = args._interval;
    _allocated_bytes = 0;

    if (_next_handler == NULL) {
        _next_handler =  (void (*)(int, siginfo_t*, void*)) OS::getSignalHandler(SIGTRAP);
    }
    OS::installSignalHandler(SIGTRAP, signalHandler);


    _in_new_tlab.install();
    _outside_tlab.install();
    _in_new_tlab2.install();
    _outside_tlab2.install();

    return Error::OK;
}

void AllocTracer::stop() {
    _in_new_tlab.uninstall();
    _outside_tlab.uninstall();
    _in_new_tlab2.uninstall();
    _outside_tlab2.uninstall();
}
