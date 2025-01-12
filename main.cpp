#include <iostream>
#include <print>

#include <expected>
#include <boost/asio.hpp>

#include <boost/process/v1/search_path.hpp>
#include <boost/process/v2.hpp>
#include <boost/program_options.hpp>

#include <boost/cobalt/main.hpp>
#include <boost/cobalt/generator.hpp>

#include <sys/user.h>
#include <sys/ptrace.h>

#include "boost_ptrace/ptrace_process.h"

boost::cobalt::generator<long> syscall_it(shk::ptrace_process &process)
{
    while (true)
    {
        auto syscall = co_await process.async_wait_syscall();
        auto number = syscall.number();
        co_await process.async_wait_syscall();
        co_yield number;
    }
}

boost::cobalt::main co_main(int argc, char **argv) {

    auto exec = co_await boost::cobalt::this_coro::executor;

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

    std::expected<void, int> result;
    if (vm.count("help")) {
        std::cout << desc << std::endl;
        co_return 1;
    }

    shk::ptrace_process child(
            exec,
            boost::process::search_path(vm["command"].as<std::string>()),
            vm["args"].as<std::vector<std::string>>()
    );
    std::println("child pid = {}", child.id());

    auto syscall_gen = syscall_it(child);
    while (syscall_gen)
    {
        auto syscall = co_await syscall_gen;
        std::println("syscall - {}", syscall);
    }

    co_return 0;
}
