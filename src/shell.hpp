#ifndef SHELL_HPP
#define SHELL_HPP

#include "json.hpp"
#include "cmdline.hpp"


void init_cmdline(cmdline::parser &cmd);
nlohmann::json get_config(const cmdline::parser &cmd);

#endif