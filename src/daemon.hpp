#ifndef DAEMON_HPP
#define DAEMON_HPP

#include <string>

#include "json.hpp"

void daemon_exec(nlohmann::json &config);
void set_user(const std::string username);


#endif 