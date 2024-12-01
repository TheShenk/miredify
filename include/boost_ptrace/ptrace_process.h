/**
 * @license
 * (C) PROTEI protei.ru
 */

#pragma once

#include <boost/process/v2/process.hpp>

#include "boost_ptrace/ptrace_launcher.h"

namespace shk
{
    template <typename Executor = boost::asio::any_io_executor>
    struct basic_ptrace_process : boost::process::basic_process<Executor>
    {

        using basic_process = boost::process::basic_process<Executor>;
        using executor_type = typename basic_process::executor_type;

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
    };

    using ptrace_process = basic_ptrace_process<>;

}
