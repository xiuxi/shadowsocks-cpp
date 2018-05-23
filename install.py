#!/usr/bin/python
#coding=utf-8
import os
import sys

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
    os.system("./config")
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
    os.system("./configure")
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
            return True
            
    return False

def check():
    bin_names = ["g++", "git", "wget", "cmake", "make", "tar"]
    for key in bin_names:
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
    
    
    
