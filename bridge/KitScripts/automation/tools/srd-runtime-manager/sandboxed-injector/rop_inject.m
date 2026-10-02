#import <stdio.h>
#import <unistd.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <errno.h>
#import <string.h>
#import <limits.h>
#import <pthread.h>
#import <pthread_spis.h>
#import <mach/mach.h>
#import <mach/error.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <mach-o/dyld_images.h>
#import <sys/utsname.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <CoreFoundation/CoreFoundation.h>

#import "pac.h"
#import "dyld.h"
#import "sandbox.h"
#import "task_utils.h"
#import "thread_utils.h"
#import "arm64.h"

vm_address_t writeStringToTask(task_t task, const char* string, size_t* lengthOut)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_address_t remoteString = (vm_address_t)NULL;
	size_t stringLen = strlen(string)+1;

	kr = vm_allocate(task, &remoteString, stringLen, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		printf("ERROR: Unable to memory for string %s: %s\n", string, mach_error_string(kr));
		return 0;
	}

	kr = vm_protect(task, remoteString, stringLen, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteString, stringLen);
		printf("ERROR: Failed to make string %s read/write: %s.\n", string, mach_error_string(kr));
		return kr;
	}

	kr = vm_write(task, remoteString, (vm_address_t)string, stringLen);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteString, stringLen);
		printf("ERROR: Failed to write string %s to memory: %s\n", string, mach_error_string(kr));
		return kr;
	}

	if(lengthOut)
	{
		*lengthOut = stringLen;
	}

	return remoteString;
}

void findRopLoop(task_t task, vm_address_t allImageInfoAddr)
{
	uint32_t inst = CFSwapInt32(0x00000014);
	ropLoop = (uint64_t)scanLibrariesForMemory(task, allImageInfoAddr, (char*)&inst, sizeof(inst), 4);
}

// Create an infinitely spinning pthread in target process
kern_return_t createRemotePthread(task_t task, vm_address_t allImageInfoAddr, thread_act_t* remotePthreadOut)
{
	kern_return_t kr = KERN_SUCCESS;

#if __arm64e__
	// GET ANY VALID THREAD STATE
	mach_msg_type_number_t validThreadStateCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state validThreadState;
	thread_act_array_t allThreadsForFindingValid;
	mach_msg_type_number_t threadCountForFindingValid;
	kr = task_threads(task, &allThreadsForFindingValid, &threadCountForFindingValid);
	if(kr != KERN_SUCCESS || threadCountForFindingValid == 0)
	{
		printf("[createRemotePthread] ERROR: failed to get threads in task: %s\n", mach_error_string(kr));
		if (kr == KERN_SUCCESS) return 1;
		return kr;
	}
	kr = thread_get_state(allThreadsForFindingValid[0], ARM_THREAD_STATE64, (thread_state_t)&validThreadState.ts_64, &validThreadStateCount);
	if(kr != KERN_SUCCESS )
	{
		printf("[createRemotePthread] ERROR: failed to get valid thread state: %s\n", mach_error_string(kr));
		return kr;
	}
	vm_deallocate(mach_task_self(), (vm_offset_t)allThreadsForFindingValid, sizeof(thread_act_array_t) * threadCountForFindingValid);
#endif

	// GATHER OFFSETS
	__unused vm_address_t libSystemPthreadAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_pthread.dylib");

	uint64_t mainThread = 0;
	if (@available(iOS 12, *)) {
		// TODO: maybe instead of this, allocate our own pthread object?
		// kinda worried about side effects here, but as long our thread doesn't
		// somehow trigger pthread_main_thread modifications, it should be fine
		uint64_t pthread_main_thread_np = remoteDlSym(task, libSystemPthreadAddr, "_pthread_main_thread_np");

		uint32_t instructions[2];
		kr = task_read(task, pthread_main_thread_np, &instructions[0], sizeof(instructions));
		if (kr != KERN_SUCCESS) {
			printf("ERROR: Failed to find main thread (1/3)\n");
			return kr;
		}

		uint64_t _main_thread_ptr = 0;
		if (!decode_adrp_ldr(instructions[0], instructions[1], pthread_main_thread_np, &_main_thread_ptr)) {
			printf("ERROR: Failed to find main thread (2/3)\n");
			return 1;
		}

		kr = task_read(task, _main_thread_ptr, &mainThread, sizeof(mainThread));
		if (kr != KERN_SUCCESS) {
			printf("ERROR: Failed to find main thread (3/3)\n");
			return kr;
		}
	}
	uint64_t _pthread_set_self = remoteDlSym(task, libSystemPthreadAddr, "__pthread_set_self");

	// ALLOCATE STACK
	vm_address_t remoteStack64 = (vm_address_t)NULL;
	kr = vm_allocate(task, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		printf("[createRemotePthread] ERROR: Unable to allocate stack memory: %s\n", mach_error_string(kr));
		return kr;
	}

	kr = vm_protect(task, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		printf("[createRemotePthread] ERROR: Failed to make remote stack writable: %s.\n", mach_error_string(kr));
		return kr;
	}

	thread_act_t bootstrapThread = 0;
	struct arm_unified_thread_state bootstrapThreadState;
	memset(&bootstrapThreadState, 0, sizeof(struct arm_unified_thread_state));

	// spawn pthread to infinite loop
	bootstrapThreadState.ash.flavor = ARM_THREAD_STATE64;
	bootstrapThreadState.ash.count = ARM_THREAD_STATE64_COUNT;
#if __arm64e__
	bootstrapThreadState.ts_64.__opaque_flags = validThreadState.ts_64.__opaque_flags;
#endif
	uint64_t sp = (remoteStack64 + (STACK_SIZE / 2));
	__unused uint64_t x2 = ropLoop;
#if __arm64e__
	if (!(bootstrapThreadState.ts_64.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH)) {
		x2 = (uint64_t)make_sym_callable((void*)x2);
	}
#endif
	__darwin_arm_thread_state64_set_sp(bootstrapThreadState.ts_64, (void*)sp);
	__darwin_arm_thread_state64_set_pc_fptr(bootstrapThreadState.ts_64, make_sym_callable((void*)_pthread_set_self));
	__darwin_arm_thread_state64_set_lr_fptr(bootstrapThreadState.ts_64, make_sym_callable((void*)ropLoop)); //when done, go to infinite loop
	bootstrapThreadState.ts_64.__x[0] = mainThread;

	//printThreadState_state(bootstrapThreadState);

	kr = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&bootstrapThreadState.ts_64, ARM_THREAD_STATE64_COUNT, &bootstrapThread);
	if(kr != KERN_SUCCESS)
	{
		printf("[createRemotePthread] ERROR: Failed to create running thread: %s.\n", mach_error_string(kr));
		return kr;
	}

	printf("[createRemotePthread] Created bootstrap thread... now waiting on finish\n");

	struct arm_unified_thread_state outState;
	kr = wait_for_thread(bootstrapThread, ropLoop, &outState);
	if(kr != KERN_SUCCESS)
	{
		printf("[createRemotePthread] ERROR: failed to wait for bootstrap thread: %s\n", mach_error_string(kr));
		return kr;
	}

	printf("[createRemotePthread] Bootstrap done!\n");

	if(remotePthreadOut) *remotePthreadOut = bootstrapThread;

	return kr;
}

// iOS 27 guards THREAD_SET_STATE on the task port supplied by
// posix_spawnattr_set_ptrauth_task_port_np.  The historical opainject path
// reused an existing remote pthread by changing its state in arbCall(), which
// now terminates the injector with EXC_GUARD before an extension can be
// consumed.  Start a new Mach thread at pthread_create_from_mach_thread
// instead.  Its real pthread invokes one existing, signed one-argument
// function in the target; no writable executable memory or existing thread
// mutation is involved.
kern_return_t callOneArgumentOnNewPthread(task_t task,
                                          vm_address_t allImageInfoAddr,
                                          uint64_t function,
                                          uint64_t argument,
                                          uint64_t *createResultOut)
{
    kern_return_t kr = KERN_SUCCESS;
    mach_msg_type_number_t validCount = ARM_THREAD_STATE64_COUNT;
    struct arm_unified_thread_state validState;
    thread_act_array_t targetThreads = NULL;
    mach_msg_type_number_t targetThreadCount = 0;
    kr = task_threads(task, &targetThreads, &targetThreadCount);
    if (kr != KERN_SUCCESS || targetThreadCount == 0) {
        printf("[safePthreadCall] ERROR: target has no readable thread state: %s\n",
               mach_error_string(kr));
        return kr == KERN_SUCCESS ? KERN_FAILURE : kr;
    }
    kr = thread_get_state(targetThreads[0], ARM_THREAD_STATE64,
                          (thread_state_t)&validState.ts_64, &validCount);
    vm_deallocate(mach_task_self(), (vm_offset_t)targetThreads,
                  sizeof(thread_act_t) * targetThreadCount);
    if (kr != KERN_SUCCESS) {
        printf("[safePthreadCall] ERROR: target thread state unavailable: %s\n",
               mach_error_string(kr));
        return kr;
    }

    vm_address_t pthreadImage = getRemoteImageAddress(
        task, allImageInfoAddr, "/usr/lib/system/libsystem_pthread.dylib");
    uint64_t createPthread = remoteDlSym(
        task, pthreadImage, "_pthread_create_from_mach_thread");
    if (!createPthread || !function || !ropLoop) {
        printf("[safePthreadCall] ERROR: required target symbols are unavailable\n");
        return KERN_FAILURE;
    }

    vm_address_t remoteStack = 0;
    vm_address_t remotePthread = 0;
    const vm_size_t stackSize = STACK_SIZE;
    kr = vm_allocate(task, &remoteStack, stackSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return kr;
    kr = vm_protect(task, remoteStack, stackSize, TRUE,
                    VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(task, remoteStack, stackSize);
        return kr;
    }
    kr = vm_allocate(task, &remotePthread, sizeof(uint64_t), VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(task, remoteStack, stackSize);
        return kr;
    }
    uint64_t zero = 0;
    kr = task_write(task, remotePthread, &zero, sizeof(zero));
    if (kr != KERN_SUCCESS) {
        vm_deallocate(task, remotePthread, sizeof(uint64_t));
        vm_deallocate(task, remoteStack, stackSize);
        return kr;
    }

    struct arm_unified_thread_state state;
    memset(&state, 0, sizeof(state));
    state.ash.flavor = ARM_THREAD_STATE64;
    state.ash.count = ARM_THREAD_STATE64_COUNT;
#if __arm64e__
    state.ts_64.__opaque_flags = validState.ts_64.__opaque_flags;
#endif
    __darwin_arm_thread_state64_set_sp(
        state.ts_64, (void *)(remoteStack + (stackSize / 2)));
    __darwin_arm_thread_state64_set_pc_fptr(
        state.ts_64, make_sym_callable((void *)createPthread));
    __darwin_arm_thread_state64_set_lr_fptr(
        state.ts_64, make_sym_callable((void *)ropLoop));
    state.ts_64.__x[0] = remotePthread;
    state.ts_64.__x[1] = 0;
    uint64_t startRoutine = function;
#if __arm64e__
    int mainUsesPtrauth = remoteMainExecutableUsesPtrauth(task, allImageInfoAddr);
    if (mainUsesPtrauth < 0) {
        printf("[safePthreadCall] ERROR: target main architecture is unavailable\n");
        vm_deallocate(task, remotePthread, sizeof(uint64_t));
        vm_deallocate(task, remoteStack, stackSize);
        return KERN_FAILURE;
    }
    if (mainUsesPtrauth && !(state.ts_64.__opaque_flags &
          __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH)) {
        startRoutine = (uint64_t)make_sym_callable((void *)startRoutine);
    }
    printf("[safePthreadCall] target-main=%s start-routine=%s\n",
           mainUsesPtrauth ? "arm64e" : "arm64",
           mainUsesPtrauth ? "target-signed" : "unsigned-canonical");
#endif
    state.ts_64.__x[2] = startRoutine;
    state.ts_64.__x[3] = argument;

    thread_act_t bootstrapThread = 0;
    kr = thread_create_running(task, ARM_THREAD_STATE64,
                               (thread_state_t)&state.ts_64,
                               ARM_THREAD_STATE64_COUNT, &bootstrapThread);
    if (kr == KERN_SUCCESS) {
        struct arm_unified_thread_state finished;
        kr = wait_for_thread(bootstrapThread, ropLoop, &finished);
        if (kr == KERN_SUCCESS && createResultOut) {
            *createResultOut = finished.ts_64.__x[0];
        }
        thread_terminate(bootstrapThread);
    }
    vm_deallocate(task, remotePthread, sizeof(uint64_t));
    vm_deallocate(task, remoteStack, stackSize);
    return kr;
}

kern_return_t arbCall(task_t task, thread_act_t targetThread, uint64_t* retOut, bool willReturn, vm_address_t funcPtr, int numArgs, ...)
{
	kern_return_t kr = KERN_SUCCESS;
	if(numArgs > 8)
	{
		printf("[arbCall] ERROR: Only 8 arguments are supported by arbCall\n");
		return -2;
	}
	if(!targetThread)
	{
		printf("[arbCall] ERROR: targetThread == null\n");
		return -3;
	}

	va_list ap;
	va_start(ap, numArgs);

	// suspend target thread
	thread_suspend(targetThread);

	// backup states of target thread

	mach_msg_type_number_t origThreadStateCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state origThreadState;
	kr = thread_get_state(targetThread, ARM_THREAD_STATE64, (thread_state_t)&origThreadState.ts_64, &origThreadStateCount);
	if(kr != KERN_SUCCESS)
	{
		thread_resume(targetThread);
		printf("[arbCall] ERROR: failed to save original state of target thread: %s\n", mach_error_string(kr));
		return kr;
	}

	struct arm64_thread_full_state* origThreadFullState = thread_save_state_arm64(targetThread);
	if(!origThreadFullState)
	{
		thread_resume(targetThread);
		printf("[arbCall] ERROR: failed to backup original state of target thread\n");
		return kr;
	}

	// prepare target thread for arbitary call

	// allocate stack
	vm_address_t remoteStack = (vm_address_t)NULL;
	kr = vm_allocate(task, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		thread_resume(targetThread);
		printf("[arbCall] ERROR: Unable to allocate stack memory: %s\n", mach_error_string(kr));
		return kr;
	}

	// make stack read / write
	kr = vm_protect(task, remoteStack, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		vm_deallocate(task, remoteStack, STACK_SIZE);
		thread_resume(targetThread);
		printf("[arbCall] ERROR: Failed to make remote stack writable: %s.\n", mach_error_string(kr));
		return kr;
	}

	// abort any existing syscalls by target thread, thanks to Linus Henze for this suggestion :P
	thread_abort(targetThread);

	// set state for arb call
	struct arm_unified_thread_state newState = origThreadState;
	uint64_t sp = remoteStack + (STACK_SIZE / 2);
	__darwin_arm_thread_state64_set_sp(newState.ts_64, (void*)sp);
	__darwin_arm_thread_state64_set_pc_fptr(newState.ts_64, make_sym_callable((void*)funcPtr));
	__darwin_arm_thread_state64_set_lr_fptr(newState.ts_64, make_sym_callable((void*)ropLoop));

	// write arguments into registers
	for (int i = 0; i < numArgs; i++)
	{
		newState.ts_64.__x[i] = va_arg(ap, uint64_t);
	}

	kr = thread_set_state(targetThread, ARM_THREAD_STATE64, (thread_state_t)&newState.ts_64, ARM_THREAD_STATE64_COUNT);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		vm_deallocate(task, remoteStack, STACK_SIZE);
		thread_resume(targetThread);
		printf("[arbCall] ERROR: failed to set state for thread: %s\n", mach_error_string(kr));
		return kr;
	}

	printf("[arbCall] Set thread state for arbitary call\n");
	//printThreadState(targetThread);

	thread_act_array_t cachedThreads;
	mach_msg_type_number_t cachedThreadCount;
	kr = task_threads(task, &cachedThreads, &cachedThreadCount);
	if (kr != KERN_SUCCESS) return kr;

	suspend_threads_except_for(cachedThreads, cachedThreadCount, targetThread);

	// perform arbitary call
	thread_resume(targetThread);
	printf("[arbCall] Started thread, waiting for it to finish...\n");

	// wait for arbitary call to finish (or not)
	struct arm_unified_thread_state outState;
	if (willReturn)
	{
		kr = wait_for_thread(targetThread, ropLoop, &outState);
		if(kr != KERN_SUCCESS)
		{
			free(origThreadFullState);
			printf("[arbCall] ERROR: failed to wait for thread to finish: %s\n", mach_error_string(kr));
			return kr;
		}

		// extract return value from state if needed
		if(retOut)
		{
			*retOut = outState.ts_64.__x[0];
		}
	}
	else
	{
		kr = wait_for_thread(targetThread, 0, &outState);
		printf("[arbCall] pthread successfully did not return with code %d (%s)\n", kr, mach_error_string(kr));
	}

	resume_threads_except_for(cachedThreads, cachedThreadCount, targetThread);

	vm_deallocate(mach_task_self(), (vm_offset_t)cachedThreads, sizeof(thread_act_array_t) * cachedThreadCount);

	// release fake stack as it's no longer needed
	vm_deallocate(task, remoteStack, STACK_SIZE);

	if (willReturn)
	{
		// suspend target thread
		thread_suspend(targetThread);
		thread_abort(targetThread);

		// restore states of target thread to what they were before the arbitary call
		bool restoreSuccess = thread_restore_state_arm64(targetThread, origThreadFullState);
		if(!restoreSuccess)
		{
			printf("[arbCall] ERROR: failed to revert to old thread state\n");
			return kr;
		}

		// resume thread again, process should continue executing as before
		//printThreadState(targetThread);
		thread_resume(targetThread);
	}

	return kr;
}

void prepareForMagic(task_t task, vm_address_t allImageInfoAddr)
{
	// FIND INFINITE LOOP ROP GADGET
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		findRopLoop(task, allImageInfoAddr);
	});
	printf("[prepareForMagic] done, ropLoop: 0x%llX\n", ropLoop);
}

bool sandboxFixup(task_t task, pid_t pid, const char* dylibPath,
                  vm_address_t allImageInfoAddr)
{
	int readExtensionNeeded = sandbox_check(pid, "file-read-data", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);
	int executableExtensionNeeded = sandbox_check(pid, "file-map-executable", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);

	int retval = 0;
	vm_address_t libSystemSandboxAddr = 0;
	uint64_t sandbox_extension_consumeAddr = 0;
	if (readExtensionNeeded || executableExtensionNeeded) {
		libSystemSandboxAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_sandbox.dylib");
		sandbox_extension_consumeAddr = remoteDlSym(task, libSystemSandboxAddr, "_sandbox_extension_consume");
		printf("[sandboxFixup] applying sandbox extension(s)! sandbox_extension_consume: 0x%llX\n", sandbox_extension_consumeAddr);
	}

	if (readExtensionNeeded) {
		char* extString = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath, 0);
		if (!extString) {
			printf("[sandboxFixup] ERROR: could not issue read extension\n");
			return false;
		}
		size_t remoteExtStringSize = 0;
		vm_address_t remoteExtString = writeStringToTask(task, (const char*)extString, &remoteExtStringSize);
		if(remoteExtString)
		{
				uint64_t createResult = 0;
				kern_return_t callResult = callOneArgumentOnNewPthread(
					task, allImageInfoAddr, sandbox_extension_consumeAddr,
					remoteExtString, &createResult);
				for (int attempt = 0; attempt < 50 &&
					 sandbox_check(pid, "file-read-data",
					 SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
					 dylibPath) != 0; attempt++) usleep(20000);
				vm_deallocate(task, remoteExtString, remoteExtStringSize);

				int stillDenied = sandbox_check(
					pid, "file-read-data",
					SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);
				printf("[sandboxFixup] safe read extension call=%d create=%llu denied=%d\n",
					callResult, createResult, stillDenied);
				retval |= (callResult != KERN_SUCCESS || createResult != 0 || stillDenied != 0);
		}
	}
	else {
		printf("[sandboxFixup] read extension not needed, skipping...\n");
	}

	if (executableExtensionNeeded) {
		char* extString = sandbox_extension_issue_file("com.apple.sandbox.executable", dylibPath, 0);
		if (!extString) {
			printf("[sandboxFixup] ERROR: could not issue executable extension\n");
			return false;
		}
		size_t remoteExtStringSize = 0;
		vm_address_t remoteExtString = writeStringToTask(task, (const char*)extString, &remoteExtStringSize);
		if(remoteExtString)
		{
				uint64_t createResult = 0;
				kern_return_t callResult = callOneArgumentOnNewPthread(
					task, allImageInfoAddr, sandbox_extension_consumeAddr,
					remoteExtString, &createResult);
				for (int attempt = 0; attempt < 50 &&
					 sandbox_check(pid, "file-map-executable",
					 SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
					 dylibPath) != 0; attempt++) usleep(20000);
				vm_deallocate(task, remoteExtString, remoteExtStringSize);

				int stillDenied = sandbox_check(
					pid, "file-map-executable",
					SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);
				printf("[sandboxFixup] safe executable extension call=%d create=%llu denied=%d\n",
					callResult, createResult, stillDenied);
				retval |= (callResult != KERN_SUCCESS || createResult != 0 || stillDenied != 0);
		}
	}
	else {
		printf("[sandboxFixup] executable extension not needed, skipping...\n");
	}

	return retval == 0;
}

bool injectDylibViaRop(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
{
	prepareForMagic(task, allImageInfoAddr);

	if (!sandboxFixup(task, pid, dylibPath, allImageInfoAddr)) {
		printf("[injectDylibViaRop] ERROR: sandbox adaptation failed\n");
		return false;
	}

	printf("[injectDylibViaRop] sandbox adaptation complete\n");
	return true;
}

bool loadDylibViaPthread(task_t task, pid_t pid, const char* dylibPath,
		vm_address_t allImageInfoAddr)
{
	prepareForMagic(task, allImageInfoAddr);
	vm_address_t libDyld = getRemoteImageAddress(
		task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");
	uint64_t dlopenAddress = remoteDlSym(task, libDyld, "_dlopen");
	if (!libDyld || !dlopenAddress) {
		printf("[loadDylibViaPthread] ERROR: target dlopen is unavailable\n");
		return false;
	}

	size_t remotePathSize = 0;
	vm_address_t remotePath = writeStringToTask(task, dylibPath, &remotePathSize);
	if (!remotePath) return false;

	uint64_t createResult = 0;
	kern_return_t callResult = callOneArgumentOnNewPthread(
		task, allImageInfoAddr, dlopenAddress, remotePath, &createResult);
	bool loaded = false;
	for (int attempt = 0; attempt < 100 && callResult == KERN_SUCCESS &&
			createResult == 0; attempt++) {
		if (getRemoteImageAddress(task, allImageInfoAddr, dylibPath) != 0) {
			loaded = true;
			break;
		}
		usleep(20000);
	}
	vm_deallocate(task, remotePath, remotePathSize);
	printf("[loadDylibViaPthread] call=%d create=%llu image=%d pid=%d\n",
		callResult, createResult, loaded, pid);
	return callResult == KERN_SUCCESS && createResult == 0 && loaded;
}
