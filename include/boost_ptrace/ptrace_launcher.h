/**
 * @license
 * (C) PROTEI protei.ru
 */

#pragma once

#include <sys/ptrace.h>

#include <boost/process/v2.hpp>
#include <boost/system/error_code.hpp>

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
