#include <ctype.h>

#include <iostream>
#include <string>
#include <fstream>
#include <algorithm>
#include <map>

#include "easylogging++.hpp"
#include "cryptor.hpp"
#include "shell.hpp"

static const std::string version()
{
    std::string name = "shadowsocksc++";
    std::string version = "3.0.0";
    return name + version;
}

void init_cmdline(cmdline::parser &cmd)
{
    cmd.add<std::string>("config", 'c', "path to config file, default: null", false, "");   
    cmd.add<int>("server_port", 'p', "server port, default: 8388", false, 8388, cmdline::range(1, 65535));
    cmd.add<std::string>("server", 's', "server address, default: 0.0.0.0", false, "0.0.0.0");  
    cmd.add<std::string>("password", 'k', "password, default: null", false, "");
    cmd.add<std::string>("method", 'm', 
                        "encryption method, default: xchacha20-ietf-poly1305\n\
                           Sodium:\n\
                               chacha20-poly1305, chacha20-ietf-poly1305,\n\
                               xchacha20-ietf-poly1305, sodium:aes-256-gcm,\n\
                               salsa20, chacha20, chacha20-ietf, xchacha20\n\
                           OpenSSL:\n\
                               aes-{128|192|256}-gcm, aes-{128|192|256}-cfb,\n\
                               aes-{128|192|256}-ofb, aes-{128|192|256}-ctr,\n\
                               aes-{128|192|256}-ocb, camellia-{128|192|256}-cfb,\n\
                               des-cfb, idea-cfb, rc2-cfb, seed-cfb, rc4,\n\
                               rc4-md5, table, bf-cfb, cast5-cfb",
                        false, "xchacha20-ietf-poly1305");                            
    cmd.add("one_time_auth", 'a', "one time auth");
    cmd.add<int>("timeout", 't', "timeout in seconds, default: 300", false, 300);  
    cmd.add("fast_open", '\0', "use TCP_FASTOPEN, requires Linux 3.7+");
    cmd.add<int>("workers", '\0', "number of progress to run, default: 1", false, 1);    
    cmd.add<std::string>("manager_address", '\0', "optional server manager UDP address", false, "");      
    cmd.add<std::string>("user", '\0', "username to run as", false, ""); 
    cmd.add<std::string>("forbidden_ip", '\0', "comma seperated IP list forbidden to connect, default: 127.0.0.0/8,::1/128", false, "127.0.0.0/8,::1/128");
    cmd.add<std::string>("daemon", 'd', "daemon mode: start/stop/restart, default: null", false, "", cmdline::oneof<std::string>("start", "stop", "restart"));
    cmd.add<std::string>("pid_file", '\0', "pid file for daemon mode, default: /var/run/shadowsocksc++.pid", false, "/var/run/shadowsocksc++.pid");     
    cmd.add<std::string>("log_file", '\0', "pid file for daemon mode, default: /var/log/shadowsocksc++.log", false, "/var/log/shadowsocksc++.log");          
    cmd.add("quiet", 'q', "quiet mode, only show warnings/info");
    cmd.add("verbose", 'v', "verbose mode, show more information"); 
    cmd.add("prefer_ipv6", '\0', "resolve ipv6 address first");
    cmd.add("version", '\0', "show version information");
    cmd.footer("\nA fast tunnel proxy that helps you bypass firewalls.\nYou can supply configurations via either config file or command line arguments.");
    cmd.set_program_name("ssc++");
}

static void check_config(nlohmann::json &config, const cmdline::parser &cmd)
{
    if (!config["daemon"].is_null() && config["daemon"] == "stop")
        return;
    
    if (config["password"].get<std::string>().empty() 
        && config["port_password"].empty() 
        && config["manager_address"].get<std::string>().empty())
    {
        LOG(ERROR) << "password or port_password not specified";
        std::cout << cmd.usage();
        exit(1);
    }
        
    if (config["server"] == "127.0.0.1" || config["server"] == "localhost")
        LOG(WARNING) << "warning: server set to listen on " 
                     << config["server"] << ":" << config["server_port"][0] 
                     << "are you sure?"; 
                     
    std::string password = config["password"];
    for (auto &c : password)
        c = tolower(c);
      
    if (password == "mypassword")
    {
        LOG(ERROR) << "DON\'T USE DEFAULT PASSWORD! Please change it in your config.json!";
        exit(1);
    }

    try
    {       
        try_cipher(config["password"], config["method"]);
    }
    catch (std::exception &e)
    {
        LOG(ERROR) <<  e.what();
        cmd.usage();
        exit(1);
    }
}

nlohmann::json get_config(const cmdline::parser &cmd)
{
    if (cmd.exist("version"))
    {
        std::cout << version() << std::endl;
        exit(0);
    }
    
    std::string config_path = cmd.get<std::string>("config").empty() ? "config.json" : cmd.get<std::string>("config");
    
    if (config_path != "config.json")
    {
        LOG(INFO) << "loading config from " << config_path;
    }
    
    nlohmann::json config;
    std::ifstream fin_config(config_path);
    
    if (fin_config)
    {
        try 
        {
           fin_config >> config;
        }
        catch (nlohmann::json::parse_error &e)
        {
            LOG(ERROR) << "json parse error: " << e.what();
            config.clear();
        }
    }
    else
    {
        LOG(INFO) << "open config file error";
    }
   
    
    if (config["server_port"].is_null() || cmd.get<int>("server_port") != 8388)
    {
        config["server_port"] = {cmd.get<int>("server_port")}; 
    }  
    
    if (config["server"].is_null() || cmd.get<std::string>("server") != "0.0.0.0")
    {
        config["server"] = cmd.get<std::string>("server");
    }
    
    if (config["dns_server"].is_null())
    {
        config["dns_server"] = nlohmann::json::array();
    }
    
    if (config["password"].is_null() || cmd.get<std::string>("password") != "")
    {
        config["password"] = cmd.get<std::string>("password");
    }
    
    if (config["port_password"].is_null())
    {
        config["port_password"] = nlohmann::json::object();
    }

    if (config["method"].is_null() || cmd.get<std::string>("method") != "xchacha20-ietf-poly1305")
    {
        config["method"] = cmd.get<std::string>("method");
    }
    std::string method = config["method"];
    for (auto &c : method)
        c = tolower(c);
    config["method"] = method;

    if (config["timeout"].is_null() || cmd.get<int>("timeout") != 300)
    {
        config["timeout"] = cmd.get<int>("timeout");
    }
    
    if (config["workers"].is_null() || cmd.get<int>("workers") != 1)
    {
        config["workers"] = cmd.get<int>("workers");
    }
    
    if (config["manager_address"].is_null() || cmd.get<std::string>("manager_address") != "")
    {
        config["manager_address"] = cmd.get<std::string>("manager_address");
    }
    
    if (config["user"].is_null() || cmd.get<std::string>("user") != "")
    {
        config["user"] = cmd.get<std::string>("user");
    }
    
    if (config["forbidden_ip"].is_null() || cmd.get<std::string>("forbidden_ip") != "127.0.0.0/8,::1/128")
    {
        config["forbidden_ip"] = cmd.get<std::string>("forbidden_ip");
    }
    
    if (cmd.exist("daemon"))
    {
        config["daemon"] = cmd.get<std::string>("daemon");
    }
    
    if (config["pid_file"].is_null() || cmd.get<std::string>("pid_file") != "/var/run/shadowsocksc++.pid")
    {
        config["pid_file"] = cmd.get<std::string>("pid_file");
    }
    
    if (config["log_file"].is_null() || cmd.get<std::string>("log_file") != "/var/log/shadowsocksc++.log")
    {
        config["log_file"] = cmd.get<std::string>("log_file");
    }
    
    int v_count = 0;
    if (cmd.exist("verbose"))
    {
        v_count += 1;
        config["verbose"] = v_count;
    }
    else if (cmd.exist("quiet"))
    {
        v_count -= 1;
        config["verbose"] = v_count;
    }
    else if (config["verbose"].is_null())
    {
        config["verbose"] = 0; 
    }
    
    if (cmd.exist("one_time_auth"))
    {
        config["one_time_auth"] = true;
    }
    else if (config["one_time_auth"] .is_null())
    {
        config["one_time_auth"]  = false; 
    }
    
    if (cmd.exist("fast_open"))
    {
        config["fast_open"] = true;
    }
    else if (config["fast_open"].is_null())
    {
        config["fast_open"] = false;
    } 
    
    if (cmd.exist("prefer_ipv6"))
    {
        config["prefer_ipv6"] = true;
    }
    else if (config["prefer_ipv6"].is_null())
    {
        config["prefer_ipv6"] = false;
    }
     
    el::Configurations defaultConf;
    el::Loggers::addFlag(el::LoggingFlag::HierarchicalLogging);
    if (config["verbose"] >= 2)
    {
        el::Loggers::setLoggingLevel(el::Level::Global);
        defaultConf.setGlobally(el::ConfigurationType::Format, "%fbase %line %func\n%datetime{%Y-%M-%d %H:%m:%s}    %level: %msg");
    }        
    else if (config["verbose"] == 1)
    {
        el::Loggers::setLoggingLevel(el::Level::Debug);
        defaultConf.setGlobally(el::ConfigurationType::Format, "%fbase %line %func\n%datetime{%Y-%M-%d %H:%m:%s}    %level: %msg");
    }        
    else if (config["verbose"] == -1)
    {
        el::Loggers::setLoggingLevel(el::Level::Warning);
    }
    else if (config["verbose"] <= -2)
    {
        el::Loggers::setLoggingLevel(el::Level::Info);
    }        
    else 
        el::Loggers::setLoggingLevel(el::Level::Error); 

    el::Loggers::setDefaultConfigurations(defaultConf, true);

    check_config(config, cmd);
    
    return config;
}






