#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <elysium/syscall.h>

namespace mlibc {

    void sys_libc_log(const char *message) {
        for(int i = 0; i < 9; i++) syscall1(SYSCALL_DBG, "mlibc :: "[i]);
        for(int i = 0; message[i]; i++) syscall1(SYSCALL_DBG, message[i]);
        syscall1(SYSCALL_DBG, '\n');
    }

    [[noreturn]] void sys_libc_panic() {
        syscall1(SYSCALL_EXIT, -0xDEAD);
        __builtin_unreachable();
    }

    [[noreturn]] void sys_exit(int status) {
        syscall1(SYSCALL_EXIT, status);
        __builtin_unreachable();
    }

    int sys_tcb_set(void *pointer [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_tcb_set called\n" << frg::endlog;
        return -1;
    }

    int sys_futex_wait(int *pointer [[maybe_unused]], int expected [[maybe_unused]], const struct timespec *time [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_futex_wait called\n" << frg::endlog;
        return -1;
    }

    int sys_futex_wake(int *pointer [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_futex_wake called\n" << frg::endlog;
        return -1;
    }

    int sys_anon_allocate(size_t size, void **pointer) {
        syscall_return_t ret = syscall1(SYSCALL_VMM_MAP, size);
        if(ret.errno != 0) return -ret.errno;
        *pointer = (void *) ret.value;
        return 0;
    }

    int sys_anon_free(void *pointer [[maybe_unused]], size_t size [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_anon_free called\n" << frg::endlog;
        return -1;
    }

    int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
        syscall_return_t ret = syscall1(SYSCALL_OPEN, (syscall_int_t) pathname);
        if(ret.errno) return -ret.errno;
        *fd = ret.value;
        return 0;
    }

    int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
        syscall_return_t ret = syscall3(SYSCALL_READ, (syscall_int_t) fd, (syscall_int_t) buf, (syscall_int_t) count);
        if(ret.errno) return -ret.errno;
        *bytes_read = ret.value;
        return 0;
    }

    int sys_write(int fd [[maybe_unused]], const void *buf [[maybe_unused]], size_t count [[maybe_unused]], ssize_t *bytes_written [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_write called\n" << frg::endlog;
        return -1;
    }

    int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
        syscall_return_t ret = syscall3(SYSCALL_SEEK, fd, offset, whence);
        if(ret.errno) return -ret.errno;
        *new_offset = ret.value;
        return 0;
    }

    int sys_close(int fd [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_close called\n" << frg::endlog;
        return -1;
    }

    int sys_stat(fsfd_target fsfdt [[maybe_unused]], int fd [[maybe_unused]], const char *path [[maybe_unused]], int flags [[maybe_unused]], struct stat *statbuf [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_stat called\n" << frg::endlog;
        return -1;
    }

    // mlibc assumes that anonymous memory returned by sys_vm_map() is zeroed by the kernel / whatever is behind the sysdeps
    int sys_vm_map(void *hint [[maybe_unused]], size_t size [[maybe_unused]], int prot [[maybe_unused]], int flags [[maybe_unused]], int fd [[maybe_unused]], off_t offset [[maybe_unused]], void **window [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_vm_map called\n" << frg::endlog;
        return -1;
    }

    int sys_vm_unmap(void *pointer [[maybe_unused]], size_t size [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_vm_unmap called\n" << frg::endlog;
        return -1;
    }

    int sys_vm_protect(void *pointer [[maybe_unused]], size_t size [[maybe_unused]], int prot [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_vm_protect called\n" << frg::endlog;
        return -1;
    }

    int sys_clock_get(int clock [[maybe_unused]], time_t *secs [[maybe_unused]], long *nanos [[maybe_unused]]) {
        mlibc::infoLogger() << "unimplemented sys_clock_get called\n" << frg::endlog;
        return -1;
    }

}