#pragma once

#include <expected>

#include <boost/asio.hpp>
#include <boost/process/v2/process.hpp>

#include "boost_ptrace/ptrace_launcher.h"

namespace shk
{
    class syscall_type {

    public:

        explicit syscall_type(boost::process::pid_type pid)
        : pid_(pid) {}

        auto number() {
            return regs().orig_rax;
        }

    private:

        const user_regs_struct &regs() {
            if (regs_) {
                return *regs_;
            }

            user_regs_struct regs{};
            if (ptrace(PTRACE_GETREGS, pid_, NULL, &regs) < 0) {
                boost::system::error_code code{errno, boost::system::system_category()};
                throw boost::system::system_error{code, "ptrace(PTRACE_GETREGS) call exited with error"};
            }

            regs_ = regs;
            return *regs_;
        }

    private:

        std::optional<user_regs_struct> regs_;
        boost::process::pid_type pid_;

    };

    template <typename Executor = boost::asio::any_io_executor>
    class basic_ptrace_process : boost::process::basic_process<Executor>
    {

    public:

        using basic_process = boost::process::basic_process<Executor>;
        using executor_type = typename basic_process::executor_type;

        using basic_process::id;
        using basic_process::handle;
        using basic_process::get_executor;

        /// Construct a child from a property list and launch it using the default launcher..
        template<typename Args, typename ... Inits>
        explicit basic_ptrace_process(
            executor_type executor,
            const boost::filesystem::path& exe,
            Args&& args,
            Inits&&... inits)
            : boost::process::basic_process<Executor>(boost::process::default_process_launcher()(executor, exe, std::forward<Args>(args), ptrace_launcher{}, std::forward<Inits>(inits)...))
            , signals_(executor, SIGCHLD)
        {
        }

        template <boost::asio::completion_token_for<void(syscall_type)> Token = boost::asio::default_completion_token_t<executor_type>>
        auto async_wait_syscall(int signal = 0, Token &&token = boost::asio::default_completion_token_t<executor_type>()) {
            if (ptrace(PTRACE_SYSCALL, id(), nullptr, signal) < 0) {
                boost::system::error_code code{errno, boost::system::system_category()};
                throw boost::system::system_error{code, "ptrace(PTRACE_SYSCALL) call exited with error"};
            }

            return boost::asio::async_compose<Token, void(syscall_type)>(async_wait_syscall_op{id(), signals_},
                                                     token, get_executor());
        }

    private:
        struct async_wait_syscall_op {

            boost::process::pid_type pid_;
            boost::asio::signal_set &signals_;

            template <typename Self>
            void operator()(Self& self) {
                signals_.async_wait([this, &self] (boost::system::error_code code, int signal) {
                    self.complete(syscall_type{pid_});
                });
            }
        };

    private:
        boost::asio::signal_set signals_;
    };

    using ptrace_process = basic_ptrace_process<>;

}
