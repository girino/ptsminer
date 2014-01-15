Debian install of Protoshares Pool Miner (PTS Miner) with GPU mining
====================================================================

Ubuntu 12.04 LTS x86_64
-----------------------
1) Install AMD or NVidia SDK

For NVidia, follow instructions on 

http://docs.nvidia.com/cuda/cuda-getting-started-guide-for-linux/index.html#package-manager-installation

For AMD, follow instructions on

http://developer.amd.com/tools-and-sdks/heterogeneous-computing/amd-accelerated-parallel-processing-app-sdk/

2) Add OpenCL to lib path:

NVidia:

export PATH=/usr/local/cuda-5.5/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/cuda-5.5/lib64:$LD_LIBRARY_PATH

(you might add these lines on ~/.bashrc so they are run at every login)

AMD:

???

3) Install other dependencies:

apt-get install build-essential libboost1.48-all-dev yasm opencl-headers

4) Compile the miner:

cd ptsminer/src
make -f makefile.unix

5) Run:

./ptsminer -u your_pts_address -a gpu

Mac OSX
=======

1) Install mac ports:

Follow instructions on 

http://www.macports.org/install.php

2) Install dependencies

sudo port install yasm
sudo port install boost

3) Compile the miner:

cd ptsminer/src
make -f makefile.osx

Windows with Cygwin64
=====================

1) Install AMD or NVidia SDK

For NVidia, follow instructions on 

http://docs.nvidia.com/cuda/cuda-getting-started-guide-for-microsoft-windows/index.html#installing-cuda-development-tools

For AMD, follow instructions on

http://developer.amd.com/tools-and-sdks/heterogeneous-computing/amd-accelerated-parallel-processing-app-sdk/

2) Add OpenCL to lib path:

NVidia:

export PATH=/cygdrive/c/PATH_TO_SDK/bin:$PATH
export LD_LIBRARY_PATH=/cygdrive/c/PATH_TO_SDK/lib:$LD_LIBRARY_PATH

(you might add these lines on ~/.bashrc so they are run at every login)

AMD:

???

3) Install all boost/libboost packages, gcc, g++ and yasm using the GUI installer

4) Compile the miner:

cd ptsminer/src
make -f makefile.cygwin
