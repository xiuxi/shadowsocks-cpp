#include <sys/types.h> 
#include <signal.h> 
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>  
#include <pwd.h>
#include <grp.h>

#include <exception>
#include <vector>

#include "easylogging++.hpp"
#include "common.hpp"
#include "daemon.hpp"


static int write_pid_file(const std::string &pid_file, const pid_t pid)
{
    int fd = open(pid_file.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR); 
    if (fd < 0)
    {
        LOG(ERROR) << "file open error: " << get_std_error_str();
        exit(1);
    }

    int flags = fcntl(fd, F_GETFD); 
    if (flags < 0)
    {
        LOG(ERROR) << "fcntl error: " << get_std_error_str();
        exit(1);
    }
    flags |= FD_CLOEXEC; 
                                                     
    int r = fcntl(fd, F_SETFD, flags);
    if (r < 0)
    {
        LOG(ERROR) << "fcntl error: " << get_std_error_str();
        exit(1); 
    }

    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;
    lock.l_pid = pid;

    if (fcntl(fd, F_SETLK, &lock) < 0)
    {
        pid_t r_pid = 0;  
        if (read(fd, (void *)&r_pid, sizeof(pid_t)) < 0)
        {
            LOG(ERROR) << "read error" << get_std_error_str();
            exit(1);
        }

        if (r_pid)
            LOG(ERROR) << "already started at pid: " << r_pid;
        else
            LOG(ERROR) << "already started";

        close(fd);

        return -1;   
    } 

    if (ftruncate(fd, 0))
    {
        LOG(ERROR) << "ftruncate error: " <<get_std_error_str();
        exit(1);
    }
    
    if (write(fd, &pid, sizeof(pid)) != sizeof(pid)) 
    {
        LOG(ERROR) << "write pid to file error : " << get_std_error_str();
        exit(1);
    }

    return 0;
}

static void handle_exit(int signum)
{
    if (signum == SIGTERM)
        exit(0);

    exit(1);
}

static void daemon_start(const std::string &pid_file, const std::string &log_file)
{
    struct sigaction act_sigint;
    struct sigaction act_sigterm;
    memset(&act_sigint, 0, sizeof(act_sigint));
    memset(&act_sigterm, 0, sizeof(act_sigterm));
    act_sigint.sa_handler = handle_exit;
    act_sigterm.sa_handler = handle_exit;

    if (sigaction(SIGINT, &act_sigint, nullptr) < 0) 
    {
        LOG(ERROR) << "sigaction error: " << get_std_error_str();
        exit(1);
    }
    if (sigaction(SIGTERM, &act_sigterm, nullptr) < 0) 
    {
        LOG(ERROR) << "sigaction error: " << get_std_error_str();
        exit(1);
    }

    // fork only once because we are sure parent will exit
    pid_t pid;
    pid_t ppid;

    pid = fork();
    if (pid == -1) 
    {
        LOG(ERROR) << "fork error: " << get_std_error_str();
        exit(1);
    }

    //parent waits for its child
    if (pid > 0)
    {
        sleep(5); 
        exit(0);
    }

    // child signals its parent to exit
    ppid = getppid(); 
    pid = getpid();  
    if (write_pid_file(pid_file, pid) != 0)
    {
        LOG(ERROR) << "write_pid_file error: " << get_std_error_str();
        kill(ppid, SIGINT);
        exit(1);                 
    }

    if (setsid() < 0)
    {
        LOG(ERROR) << "setsid error: " << get_std_error_str();
        exit(1);
    }
    
    //SIG_IGN specifies that the signal should be ignored
    struct sigaction act_sighup;
    memset(&act_sighup, 0, sizeof(act_sighup));
    act_sighup.sa_handler = SIG_IGN;

    if (sigaction(SIGHUP, &act_sighup, nullptr) < 0) 
    {
        LOG(ERROR) << "sigaction error: " << get_std_error_str();
        exit(1);
    }

    LOG(INFO) << "started";
    kill(ppid, SIGTERM);

    fclose(stdin); 
  
    if (!freopen(log_file.c_str(), "a", stdout))
    {
        LOG(ERROR) << "freopen error: " << get_std_error_str();
        exit(1);
    } 
    if (!freopen(log_file.c_str(), "a", stderr))
    {
        LOG(ERROR) << "freopen error: " << get_std_error_str();
        exit(1);
    } 
}

void static daemon_stop(const std::string &pid_file)
{
    int fd = open(pid_file.c_str(), O_RDONLY); 
    if ( fd < 0)
    {
        if (errno == ENOENT)
        {
            LOG(ERROR) << "not running";
            return;
        }
        
        LOG(ERROR) << "open error: " << get_std_error_str();
        exit(1);
    }

    pid_t pid = 0;
    int ret = read(fd, &pid, sizeof(pid_t));
    if (ret < 0)
    {
        LOG(ERROR) << "read error: " << get_std_error_str();
        exit(1);
    }
    else if (ret == 0)
    {
        LOG(ERROR) << "not running";
        return ;
    }

    if (pid > 0)
    {
        if (kill(pid, SIGTERM) < 0)
        {
            if (errno == ESRCH)
            {
                LOG(ERROR) << "not running";
                return;
            }

            LOG(ERROR) << "kill error: " << get_std_error_str();
            exit(1);
        }
    }
    else
    {
        LOG(ERROR) << "pid is not positive: " <<  pid;
        exit(1);
    } 
  
    //sleep for maximum 10s
    bool kill_ok = false;
    for (int i = 0; i < 200; i++)
    {
        if (kill(pid, SIGTERM) < 0)
        {
            if (errno == ESRCH)
            {
                kill_ok = true;
                break;
            }
        }
        usleep(50000);//0.05s
    }
    if (!kill_ok)
    {
        LOG(ERROR) << "timed out when stopping pid:" << pid;
        exit(1);
    }

    LOG(INFO) <<"stopped";
    if (unlink(pid_file.c_str()) < 0)
    {
        LOG(ERROR) << "remove pid file error: " << get_std_error_str();
        exit(1);
    }
}

void daemon_exec(nlohmann::json &config)
{
    if (config["daemon"].is_null())
        return;
    
    std::string command = config["daemon"];
    if (command.empty())
        command = "start";

    std::string pid_file = config["pid_file"];
    std::string log_file = config["log_file"];

    if (command == "start")
    {
        daemon_start(pid_file, log_file);
    }
    else if (command == "stop")
    {
        daemon_stop(pid_file);
        exit(0);
    }
    else if (command == "restart")
    {
        daemon_stop(pid_file);
        daemon_start(pid_file, log_file);
    }
    else
    {
        throw std::runtime_error("unsupported daemon command: " + command);
    }
}

void set_user(const std::string username)
{
    if (username.empty())
        return;

    auto cur_uid = getuid();
    if (cur_uid != 0)
    {
        LOG(ERROR) << "can not set user as nonroot user";
        exit(1);
    }

    struct passwd pwrec, *pwd;
    memset(&pwrec, 0, sizeof(struct passwd));
    int bufsize;
    int err;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1)          /* Value was indeterminate */
        bufsize = 16384;        /* Should be more than enough */
    
    std::vector<char> buf(bufsize);
    err = getpwnam_r(username.c_str(), &pwrec, &buf[0], bufsize, &pwd);

    if (err == 0 && pwd)
    {  
        if (pwd->pw_uid == cur_uid)
            return ;
  
        if (setgid(pwd->pw_gid) != 0) 
        {
            LOG(ERROR) << "Could not change group id to that of run_as user " <<  pwd->pw_name << "error: " <<  get_std_error_str();
            exit(1);
        }
        if (initgroups(pwd->pw_name, pwd->pw_gid) == -1) 
        {
            LOG(ERROR) << "Could not change supplementary groups for user " <<  pwd->pw_name << get_std_error_str();
            exit(1);
        }

        if (setuid(pwd->pw_uid) != 0) 
        {
            LOG(ERROR) << "Could not change user id to that of run_as user " << pwd->pw_name << "error: " <<  get_std_error_str();
            exit(1);
        }
    }
    else if (err != ERANGE) 
    {
        if (err) 
            LOG(ERROR) << "run_as user " << pwd->pw_name << " could not be found, "<<  "error: " <<  get_std_error_str();

        else 
            LOG(ERROR) << "run_as user "<< pwd->pw_name << " could not be found";

        exit(1);
    }

    else if (err == ERANGE)
    {
        LOG(ERROR) << "getpwnam_r() requires more than " << bufsize << " bytes";
        exit(1);
    } 
}