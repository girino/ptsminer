Debian install of Protoshares Pool Miner (PTS Miner) with GPU mining
====================================================================

Ubuntu 12.04 LTS x86_64
-----------------------
1) Install AMD or NVidia SDK

NVidia:

Follow instructions on 

http://docs.nvidia.com/cuda/cuda-getting-started-guide-for-linux/index.html#package-manager-installation

AMD:


2) Add OpenCL to lib path:

NVidia:

export PATH=/usr/local/cuda-5.5/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/cuda-5.5/lib64:$LD_LIBRARY_PATH

(you might add these lines on ~/.bashrc so they are run at every login)

3) Install other dependencies:

apt-get install build-essential libboost1.48-all-dev yasm opencl-headers

4) Compile the miner:

cd ptsminer/src
make -f makefile.unix

5) Run:

./ptsminer -u your_pts_address -a gpu

