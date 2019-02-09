//
// Created by Roman on 2018/4/30.
//

/*
 ============================================================================
 Name        : libinject.c
 Author      :
 Version     :
 Copyright   :
 Description : Android shared library inject helper
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/uio.h>
#include "log.h"

#define CPSR_T_MASK        ( 1u << 5 )

#if defined(__i386__)
#define pt_regs         user_regs_struct
#elif defined(__aarch64__)
#define pt_regs         user_pt_regs
#define uregs   regs
#define ARM_pc  pc
#define ARM_sp  sp
#define ARM_cpsr    pstate
#define ARM_lr      regs[30]
#define ARM_r0      regs[0]
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#endif

#if defined(__aarch64__)
const char *libc_path = "/system/lib64/libc.so";
const char *linker_path = "/system/bin/linker64";
#else
const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";
#endif


//从附加远程目标进程的内存中读取数据
//读取的数据保存在buf缓存区中
int ptrace_readdata(pid_t pid, uint8_t *src, uint8_t *buf, size_t size) {
    long i, j, remain;
    uint8_t *laddr;
    const size_t bytes_width = sizeof(long);

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / bytes_width;
    remain = size % bytes_width;

    laddr = buf;

    for (i = 0; i < j; i++) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, bytes_width);
        src += bytes_width;
        laddr += bytes_width;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, remain);
    }

    return 0;

}

//向附加调试的目标进程内存中写入数据
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size) {
    long i, j, remain;
    uint8_t *laddr;
    const size_t bytes_width = sizeof(long);

    union u {
        long val;
        char chars[bytes_width];
    } d;

    j = size / bytes_width;
    remain = size % bytes_width;

    laddr = data;

    for (i = 0; i < j; i++) {
        memcpy(d.chars, laddr, bytes_width);
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest += bytes_width;
        laddr += bytes_width;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i++) {
            d.chars[i] = *laddr++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

    }

    return 0;
}

//向附加调试的目标进程内存中写入字符串数据
int ptrace_writestring(pid_t pid, uint8_t *dest, char *str) {
    return ptrace_writedata(pid, dest, str, strlen(str) + 1);
}

/*
 * 在其他进程（远程目标进程）中调用系统函数mmap申请内存空间
 * void* mmap(void* start, size_t length, int prot, int flags, int fd, off_t offset);
 * params是已经格式化的mmap函数的参数，num_params是mmap函数的参数的个数
 * regs是远程目标进程的寄存器的数据，addr为远程目标进程中函数mmap的调用地址
 */
#if defined(__arm__) || defined(__aarch64__)
int ptrace_call(pid_t pid, uintptr_t addr, long *params, int num_params, struct pt_regs *regs) {
    int i;

#if defined(__arm__)
    int num_param_registers = 4;
#elif defined(__aarch64__)
    int num_param_registers = 8;
#endif

    for (i = 0; i < num_params && i < num_param_registers; i++) {
        regs->uregs[i] = params[i];
    }

    // push remained params onto stack
    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long);
        ptrace_writedata(pid, (void *) regs->ARM_sp, (uint8_t *) &params[i],
                         (num_params - i) * sizeof(long));
    }

    regs->ARM_pc = addr;
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;

    if (ptrace_setregs(pid, regs) == -1
        || ptrace_continue(pid) == -1) {
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}

#elif defined(__i386__)
long ptrace_call(pid_t pid, uintptr_t addr, long *params, int num_params, struct user_regs_struct * regs)
{
	regs->esp -= (num_params)* sizeof(long);
	ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params)* sizeof(long));

	long tmp_addr = 0x00;
	regs->esp -= sizeof(long);
	ptrace_writedata(pid, regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));

	regs->eip = addr;

	if (ptrace_setregs(pid, regs) == -1
		|| ptrace_continue(pid) == -1) {
		printf("error\n");
		return -1;
	}

	int stat = 0;
	waitpid(pid, &stat, WUNTRACED);
	while (stat != 0xb7f) {
		if (ptrace_continue(pid) == -1) {
			printf("error\n");
			return -1;
		}
		waitpid(pid, &stat, WUNTRACED);
	}

	return 0;
}
#else
#error "Not supported"
#endif

//获取被附加调试进程的寄存器的值
int ptrace_getregs(pid_t pid, struct pt_regs *regs) {
#if defined (__aarch64__)
    int regset = NT_PRSTATUS;
    struct iovec ioVec;

    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void*)regset, &ioVec) < 0) {
        perror("ptrace_getregs: Can not get register values");
        printf(" io %llx, %d", ioVec.iov_base, ioVec.iov_len);
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_getregs: Can not get register values");
        return -1;
    }
    return 0;
#endif
}

//设置被附加调试进程的寄存器的值
int ptrace_setregs(pid_t pid, struct pt_regs *regs) {
#if defined (__aarch64__)
    int regset = NT_PRSTATUS;
    struct iovec ioVec;

    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)regset, &ioVec) < 0) {
        perror("ptrace_setregs: Can not get register values");
        return -1;
    }
    return 0;
#else
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }
    return 0;
#endif
}

//附加的目标进程继续执行
int ptrace_continue(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

//附加目标进程
int ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("ptrace_attach");
        return -1;
    }
    int status = 0;
    waitpid(pid, &status, WUNTRACED);

    return 0;
}

//结束目标进程的附加
int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}

//获取进程加载模块的基址
void *get_module_base(pid_t pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok(line, "-");
                addr = strtoull(pch, NULL, 16);
                //LOGE("[+] %s_get_module_base: %llx\n", module_name, addr);
                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp);
    }

    return (void *) addr;
}

//获取其他进程的某加载模块中某系统函数的调用地址
void *get_remote_addr(pid_t target_pid, const char *module_name, void *local_addr) {
    void *local_handle, *remote_handle;

    local_handle = get_module_base(-1, module_name);//本地进程基址
    remote_handle = get_module_base(target_pid, module_name);//目标进程基址

    LOGE("[+] get_remote_addr: local[%llx], remote[%llx]\n", local_handle, remote_handle);

    void *ret_addr = (void *)((uintptr_t)local_addr + (uintptr_t)remote_handle - (uintptr_t)local_handle);

#if defined(__i386__)
    if (!strcmp(module_name, libc_path)) {
		ret_addr += 2;
	}
#endif
    return ret_addr;
}


//查找要注入的目标进程PID
//process_name为要查找的进程名字
int find_pid_of(const char *process_name) {
    int id;
    DIR *dir;
    FILE *fp;

    //保存进程的pid
    pid_t pid = -1;

    //保存进程名称
    char filename[32];

    //保存运行进程的命令行
    char cmdline[256];

    struct dirent *entry;

    //目标进程名不能为空
    if (process_name == NULL)
        return -1;

    //打开“/proc”目录
    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    //循环读取proc目录下的文件
    while ((entry = readdir(dir)) != NULL) {
        //将文件名字符串转整型得到进程的PID
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                //读取运行进程的命令行中的arg[0]即进程名称
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                //判断获取到的进程名称是否与要查找的目标进程名称相同
                if (strcmp(process_name, cmdline) == 0) {
                    /* process found */
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);

    return pid;
}

uint64_t ptrace_retval(struct pt_regs * regs)
{
#if defined(__arm__) || defined(__aarch64__)
    return regs->ARM_r0;
#elif defined(__i386__)
    return regs->eax;
#else
#error "Not supported"
#endif
}

uint64_t ptrace_ip(struct pt_regs * regs)
{
#if defined(__arm__) || defined(__aarch64__)
    return regs->ARM_pc;
#elif defined(__i386__)
    return regs->eip;
#else
#error "Not supported"
#endif
}

int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs)
{
    LOGE("[+] Calling %s in target process.\n", func_name);

    //在目标进程中调用函数func_name
    if (ptrace_call(target_pid, (uintptr_t)func_addr, parameters, param_num, regs) == -1)
        return -1;

    //获取附加远程目标进程此时寄存器的状态值
    if (ptrace_getregs(target_pid, regs) == -1)
        return -1;

    LOGE("[+] Target process returned from %s, return value=%llx, pc=%llx \n",
         func_name, ptrace_retval(regs), ptrace_ip(regs));
    return 0;
}

/*
* 对远程目标进程进行LibInject和函数的Hook
* library_path------------------自定义的Hook函数所在的模块（libHook.so库）的路径
* function_name-----------------Hook函数在libHook.so库中名称Hook_Api
* param-------------------------Hook函数调用所需要的参数
* param_size--------------------Hook函数调用所需要的参数的大小
*/
int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name,
                          const char *param, size_t param_size) {
    int ret = -1;
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
    void *local_handle, *remote_handle, *dlhandle;
    uint8_t *map_base;

    struct pt_regs regs, original_regs;
    long parameters[10];

    LOGE("[+] Injecting process: %d\n", target_pid);

    //附加目标进程
    if (ptrace_attach(target_pid) == -1)
        return EXIT_SUCCESS;

    //获取附加远程目标进程此时寄存器的状态值
    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    /* save original registers */
    memcpy(&original_regs, &regs, sizeof(regs));

    //获取附加远程目标进程"/system/lib/libc.so"模块中函数mmap的调用地址
    mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);
    LOGE("[+] Remote mmap address: %llx\n", mmap_addr);

    /* call mmap */
    parameters[0] = 0;    // addr
    parameters[1] = 0x4000; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot可读可写可执行
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset

    //执行mmap函数在目标进程中申请一段内存空间
    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
        goto exit;

    //保存mmap申请到内存空间的地址map_base = r0
    map_base = ptrace_retval(&regs);

    //获取附加远程目标进程中函数dlopen、函数dlsym、函数dlclose、函数dlerror的调用地址
    dlopen_addr = get_remote_addr(target_pid, linker_path, (void *)dlopen);
    dlsym_addr = get_remote_addr(target_pid, linker_path, (void *)dlsym);
    dlclose_addr = get_remote_addr(target_pid, linker_path, (void *)dlclose);
    dlerror_addr = get_remote_addr(target_pid, linker_path, (void *)dlerror);

    LOGE("[+] Get imports: dlopen: %llx, dlsym: %llx, dlclose: %llx\n, dlerror: %llx\n", dlopen_addr, dlsym_addr,
         dlclose_addr, dlerror_addr);

    printf("library path = %s\n", library_path);

    //向前面mmap出来的目标进程的内存中写入要注入的so库路径
    ptrace_writedata(target_pid, map_base, library_path, strlen(library_path) + 1);
    //设置dlopen的参数
    parameters[0] = map_base;//so库路径
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;//打开方式
    //执行dlopen函数：打开so库文件
    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;

    //将dlopen函数返回值保存在sohandle中
    void * sohandle = ptrace_retval(&regs);
    if (!sohandle) {
        if (ptrace_call_wrapper(target_pid, "dlerror", dlerror_addr, 0, 0, &regs) == -1)
            goto exit;

        uint8_t *errret = ptrace_retval(&regs);
        uint8_t errbuf[100];
        ptrace_readdata(target_pid, errret, errbuf, 100);
    }

#define FUNCTION_NAME_ADDR_OFFSET  0x100
    //向目标进程的内存空间中写入so库中的自定义Hook函数名
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, function_name, strlen(function_name) + 1);
    //设置dlsym的参数
    parameters[0] = sohandle;//so库操作句柄
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;//函数名称的地址

    //执行dlsym函数：获取so库中hook函数的地址
    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;
    //获取dlsym函数返回值，即hook函数地址
    void * hook_entry_addr = ptrace_retval(&regs);
    LOGE("hook_entry_addr = %p\n", hook_entry_addr);

#define FUNCTION_PARAM_ADDR_OFFSET  0x200
    //向目标进程的内存空间中写入Hook函数调用的参数
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, param, strlen(param) + 1);
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;

    //执行hook函数
    if (ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 1, &regs) == -1)
        goto exit;

    //执行dlclose函数
    printf("Press enter to dlclose and detach\n");
//    getchar();
    parameters[0] = sohandle;
    if (ptrace_call_wrapper(target_pid, "dlclose", dlclose, parameters, 1, &regs) == -1)
        goto exit;

    ptrace_setregs(target_pid, &original_regs);
    //结束目标进程的追踪
    ptrace_detach(target_pid);
    // inject succeeded
    ret = 0;

    exit:
    return ret;
}


int main(int argc, char **argv) {
    pid_t target_pid1,target_pid2;
    //获取目标进程的PID
    target_pid1 = find_pid_of("system_server");
    target_pid2 = find_pid_of("com.android.phone");
    //对目标进程进行注入和函数的HOOK
    inject_remote_process(target_pid1, "/data/local/tmp/libhook.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!"));
    inject_remote_process(target_pid2, "/data/local/tmp/libhook.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!"));
    return 0;
}