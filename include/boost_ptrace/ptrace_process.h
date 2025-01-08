#pragma once

#include <expected>

#include <boost/asio.hpp>
#include <boost/process/v2/process.hpp>

#include "boost_ptrace/ptrace_launcher.h"

namespace shk
{
    template <typename Executor = boost::asio::any_io_executor>
    struct basic_ptrace_process : boost::process::basic_process<Executor>
    {

        using basic_process = boost::process::basic_process<Executor>;
        using executor_type = typename basic_process::executor_type;

        using basic_process::id;
        using basic_process::handle;

        /// Construct a child from a property list and launch it using the default launcher..
        template<typename Args, typename ... Inits>
        explicit basic_ptrace_process(
            executor_type executor,
            const boost::filesystem::path& exe,
            Args&& args,
            Inits&&... inits)
            : boost::process::basic_process<Executor>(boost::process::default_process_launcher()(std::move(executor), exe, std::forward<Args>(args), ptrace_launcher{}, std::forward<Inits>(inits)...))
        {
        }

        template <boost::asio::completion_token_for<void(boost::system::error_code)> Token = boost::asio::default_completion_token_t<executor_type>>
        auto async_ptrace_syscall(int signal = 0, Token &&token = boost::asio::default_completion_token_t<executor_type>()) {
            if (ptrace(PTRACE_SYSCALL, id(), nullptr, signal) < 0) {
                boost::system::error_code code{errno, boost::system::system_category()};
                throw boost::system::system_error{code, "ptrace(PTRACE_SYSCALL) call exited with error"};
            }

            return basic_process::handle().async_wait(std::forward<Token>(token));
        }

        auto ptrace_syscall_number() {
            user_regs_struct registers;
            if (ptrace(PTRACE_GETREGS, id(), NULL, &registers) < 0) {
                boost::system::error_code code{errno, boost::system::system_category()};
                throw boost::system::system_error{code, "ptrace(PTRACE_GETREGS) call exited with error"};
            }
            return registers.orig_rax;
        }

    };

    using ptrace_process = basic_ptrace_process<>;

}
