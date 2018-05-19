#include <iostream>
#include <string>

#include "easylogging++.hpp"
#include "cmdline.hpp"
#include "shell.hpp"
#include "daemon.hpp"
#include "common.hpp"
#include "server.hpp"

INITIALIZE_EASYLOGGINGPP

int main(int argc, char *argv[])
{
    init_easylog();
    
    cmdline::parser cmd;
    init_cmdline(cmd);
    cmd.parse_check(argc, argv);
    
    auto config = get_config(cmd);
    daemon_exec(config);
    run_server(config);
    return 0; 
}

