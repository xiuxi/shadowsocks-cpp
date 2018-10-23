#!/usr/bin/python
#coding=utf-8
import os
import sys
import subprocess  

def install_opensll():
    if os.path.exists("/usr/local/include/openssl") and os.path.exists("/usr/local/lib/libcrypto.so"):
        return
    
    cur_dir = os.getcwd()
    openssl_download = "wget https://www.openssl.org/source/openssl-1.1.0h.tar.gz"
    os.system("mkdir temp")
    os.chdir(cur_dir + os.sep + "temp")
    os.system("wget https://www.openssl.org/source/openssl-1.1.0h.tar.gz")
    os.system("tar zxvf openssl-1.1.0h.tar.gz")
    os.chdir(cur_dir + os.sep + "temp" + os.sep + "openssl-1.1.0h")
    os.system("./config --prefix=/usr/local --libdir=lib --openssldir=/usr/local/ssl")
    os.system("make")
    #os.system("sudo make install") 
    #install lib and head files not doc
    os.system("sudo make install_sw")
    os.system("sudo make install_ssldirs")   

    os.chdir(cur_dir)
    os.system("rm -rf temp")
    
    if not os.path.exists("/usr/local/include/openssl") or not os.path.exists("/usr/local/lib/libcrypto.so"):
        print("install openssl error")
        sys.exit(1)
    
def install_libsodium():
    if os.path.exists("/usr/local/include/sodium") and os.path.exists("/usr/local/lib/libsodium.so"):
        return
    
    cur_dir = os.getcwd()
    libdium_download = "git clone https://github.com/jedisct1/libsodium --branch stable"
    os.system("mkdir temp")
    os.chdir(cur_dir + os.sep + "temp")
    os.system(libdium_download)
    os.chdir(cur_dir + os.sep + "temp" + os.sep + "libsodium")
    os.system("./configure --prefix=/usr/local --libdir=/usr/local/lib --includedir=/usr/local/include")
    os.system("make && make check")
    os.system("sudo make install")
   
    os.chdir(cur_dir)
    os.system("rm -rf temp")
    
    if not os.path.exists("/usr/local/include/sodium") or not os.path.exists("/usr/local/lib/libsodium.so"):
        print("install openssl error")
        sys.exit(1)
        
def find_bin(name):
    paths = ["/usr/local/bin", "/usr/bin", "/bin"]
    for path in paths:
        if os.path.exists(path + os.sep + name):
            return True, path + os.sep + name 
            
    return False, None

def check():
    gcc_compiler = find_bin("g++")
    clang_compiler = find_bin("clang++")
    compiler = None
    flag = False
    version_str =  None
    if gcc_compiler[0]: 
        compiler = gcc_compiler[1]
        try:
            out_bytes = subprocess.check_output([compiler, "-dumpversion"])
            version_str = out_bytes.decode('utf-8')
            version_str = version_str[:-1] 
            out_version = version_str.split(".")
            if len(out_version) == 1:
                out_bytes = subprocess.check_output([compiler, "-dumpfullversion"])
                version_str = out_bytes.decode('utf-8')
                version_str = version_str[:-1]
                out_version = version_str.split(".")
                if int(out_version[0]) == 4 and int(out_version[1]) >= 9 or int(out_version[0]) > 4:
                    flag = True
            elif len(out_version) >= 3:
                if int(out_version[0]) == 4 and int(out_version[1]) >= 9 or int(out_version[0]) > 4:
                    flag = True
        except subprocess.CalledProcessError as e:
            pass
    elif clang_compiler[0]:
        compiler = clang_compiler[1]
        try:
            out_bytes = subprocess.check_output([compiler, "--version"])
            version_str = out_bytes.decode('utf-8')
            version_str = version_str[:-1]
            out_version = version_str.split(" ")
            if len(out_version) >= 3:
                version_str = out_version[2].split("-")[0]
                out_version = version_str.split(".")
                if int(out_version[0]) == 3 and int(out_version[1]) >= 4 or int(out_version[0]) > 3:
                    flag = True                
        except subprocess.CalledProcessError as e:
            pass
    else:
        print("you need to install g++ 4.9-7.2 (or later) or clang 3.4-5.0 (or later)")
        sys.exit(1)
    
    if not flag:
        print("the compiler is %s, veriosn is %s, but g++ 4.9-7.2 (or later) or clang 3.4-5.0 (or later) is required \nyou have to upgrade compiler." % (compiler, version_str))
        sys.exit(1)
     
    os.system("export CXX=" + compiler)
    bin_names = ["git", "wget", "cmake", "make", "tar"]
    for key in bin_names[0]:
        if not find_bin(key):
            print("you need to install %s first" % (key))
            sys.exit(1)
     
def install():
    check()
    
    cur_dir = os.getcwd()
    if not os.path.exists(cur_dir + os.sep + "build"):
        os.system("mkdir build")
        
    os.chdir(cur_dir + os.sep + "build")
    
    install_opensll()
    install_libsodium()
    
    os.system("cmake ..")
    os.system("make")
    
    if not os.path.exists(cur_dir + os.sep + "build" + os .sep + "ssc++"):
        print("build error")
        os.system("rm -rf *")
        sys.exit(1)
    
    os.system("sudo cp ssc++ /usr/local/bin")
    os.chdir(cur_dir)
    os.system("rm -rf build")
    print("install ssc++ done")
    
if __name__ == '__main__':
    install()
    
    
    
