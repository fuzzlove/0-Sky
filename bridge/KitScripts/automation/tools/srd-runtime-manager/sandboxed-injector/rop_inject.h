extern bool injectDylibViaRop(task_t task, pid_t pid, const char* dylibPath,
                             vm_address_t allImageInfoAddr);
extern bool loadDylibViaPthread(task_t task, pid_t pid, const char* dylibPath,
                               vm_address_t allImageInfoAddr);
