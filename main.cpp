#include <iostream>
#include <print>

#include <boost/process/v1/search_path.hpp>
#include <boost/process/v2.hpp>
#include <boost/process/v2/posix/fork_and_forget_launcher.hpp>
#include <boost/program_options.hpp>
#include <boost/system/error_code.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/ptrace.h>
#include <err.h>
#include <syscall.h>

namespace shk {

    struct ptrace_launcher {

        // Called before a call to execve. A returned error will cancel the launch. Called from the child process.
        boost::system::error_code on_exec_setup(boost::process::v2::posix::default_launcher & launcher, const boost::filesystem::path &executable, const char * const * (&cmd_line)) {
            if (auto result = ptrace(PTRACE_TRACEME, 0, NULL, NULL); result < 0) {
                return boost::system::error_code{errno, boost::system::system_category()};
            }
            return boost::system::error_code{};
        }

    };

}

constexpr std::array syscall_to_name = {
        "READ",
        "WRITE",
        "OPEN",
        "CLOSE",
        "STAT",
        "FSTAT",
        "LSTAT",
        "POLL",
        "LSEEK",
        "MMAP",
        "MPROTECT",
        "MUNMAP",
        "BRK",
        "rt_SIGACTION",
        "rt_SIGPROCMASK",
        "rt_SIGRETURN",
        "IOCTL",
        "PREAD64",
        "PWRITE64",
        "READV",
        "WRITEV",
        "ACCESS",
        "PIPE",
        "SELECT",
        "sched_YIELD",
        "MREMAP",
        "MSYNC",
        "MINCORE",
        "MADVISE",
        "SHMGET",
        "SHMAT",
        "SHMCTL",
        "DUP",
        "DUP2",
        "PAUSE",
        "NANOSLEEP",
        "GETITIMER",
        "ALARM",
        "SETITIMER",
        "GETPID",
        "SENDFILE",
        "SOCKET",
        "CONNECT",
        "ACCEPT",
        "SENDTO",
        "RECVFROM",
        "SENDMSG",
        "RECVMSG",
        "SHUTDOWN",
        "BIND",
        "LISTEN",
        "GETSOCKNAME",
        "GETPEERNAME",
        "SOCKETPAIR",
        "SETSOCKOPT",
        "GETSOCKOPT",
        "CLONE",
        "FORK",
        "VFORK",
        "EXECVE",
        "EXIT",
        "WAIT4",
        "KILL",
        "UNAME",
        "SEMGET",
        "SEMOP",
        "SEMCTL",
        "SHMDT",
        "MSGGET",
        "MSGSND",
        "MSGRCV",
        "MSGCTL",
        "FCNTL",
        "FLOCK",
        "FSYNC",
        "FDATASYNC",
        "TRUNCATE",
        "FTRUNCATE",
        "GETDENTS",
        "GETCWD",
        "CHDIR",
        "FCHDIR",
        "RENAME",
        "MKDIR",
        "RMDIR",
        "CREAT",
        "LINK",
        "UNLINK",
        "SYMLINK",
        "READLINK",
        "CHMOD",
        "FCHMOD",
        "CHOWN",
        "FCHOWN",
        "LCHOWN",
        "UMASK",
        "GETTIMEOFDAY",
        "GETRLIMIT",
        "GETRUSAGE",
        "SYSINFO",
        "TIMES",
        "PTRACE",
};

void print_syscall_enter(uint64_t syscall_num)
{
    if (syscall_num < sizeof(syscall_to_name) / sizeof(syscall_to_name[0]))
        std::cout << syscall_to_name[syscall_num] << " " << syscall_num << std::endl;
    else
        std::cout << "unknown" << " " << syscall_num << std::endl;
}

void print_syscall_exit(uint64_t return_value)
{
    std::cout << " -> " << return_value << std::endl;
}

int main(int argc, char **argv) {
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            ("command", boost::program_options::value<std::string>(), "Command to run under miredo")
            ("args", boost::program_options::value<std::vector<std::string>>(), "Arguments for specified command")
            ;

    auto positional_desc = boost::program_options::positional_options_description()
            .add("command", 1)
            .add("args", -1);
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv)
                                          .options(desc)
                                          .positional(positional_desc)
                                          .run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 1;
    }

    boost::asio::io_context context;
    boost::process::process child(
            context,
            boost::process::search_path(vm["command"].as<std::string>()),
            vm["args"].as<std::vector<std::string>>(),
            shk::ptrace_launcher{}
    );

    std::cout << child.id() << std::endl;
    /* A system call tracing loop, one interation per call. */
    for (;;) {
        /* A non-portable structure defined for ptrace/GDB/strace usage mostly.
         * It allows to conveniently dump and access register state using
         * ptrace. */
        struct user_regs_struct registers;

        /* Enter syscall: continue execution until the next system call
         * beginning. Stop right before syscall.
         *
         * It's possible to change the system call number, system call
         * arguments, return value or even avoid executing the system call
         * completely. */
        if (ptrace(PTRACE_SYSCALL, child.id(), NULL, NULL) == -1)
            err(EXIT_FAILURE, "enter_syscall");
        if (waitpid(child.id(), NULL, 0) == -1)
            err(EXIT_FAILURE, "enter_syscall -> waitpid");

        /* According to the x86-64 system call convention on Linux (see man 2
         * syscall) the number identifying a syscall should be put into the rax
         * general purpose register, with the rest of the arguments residing in
         * other general purpose registers (rdi,rsi, rdx, r10, r8, r9). */
        if (ptrace(PTRACE_GETREGS, child.id(), NULL, &registers) == -1)
            err(EXIT_FAILURE, "enter_syscall -> getregs");

        /* Note how orig_rax is used here. That's because on x86-64 rax is used
         * both for executing a syscall, and returning a value from it. To
         * differentiate between the cases both rax and orig_rax are updated on
         * syscall entry/exit, and only rax is updated on exit. */
        print_syscall_enter(registers.orig_rax);

        /* Exit syscall: execute of the syscall, and stop on system
         * call exit.
         *
         * More system call tinkering possible: change the return value, record
         * time it took to finish the system call, etc. */
        if (ptrace(PTRACE_SYSCALL, child.id(), NULL, NULL) == -1)
            err(EXIT_FAILURE, "exit_syscall");
        if (waitpid(child.id(), NULL, 0) == -1)
            err(EXIT_FAILURE, "exit_syscall -> waitpid");

        /* Retrieve register state again as we want to inspect system call
         * return value. */
        if (ptrace(PTRACE_GETREGS, child.id(), NULL, &registers) == -1) {
            /* ESRCH is returned when a child terminates using a syscall and no
             * return value is possible, e.g. as a result of exit(2). */
            if (errno == ESRCH) {
                fprintf(stderr, "\nTracee terminated\n");
                break;
            }
            err(EXIT_FAILURE, "exit_syscall -> getregs");
        }

        /* Done with this system call, let the next iteration handle the next
         * one */
        print_syscall_exit(registers.rax);
    }

    return EXIT_SUCCESS;
}
