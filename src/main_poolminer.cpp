//===
// by xolokram/TB
// 2013
//===

#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <map>

#include "main_poolminer.h"
#include "CProtoshareProcessor.h"
#include "OpenCLObjects.h"

#if defined(__GNUG__) && !defined(__MINGW32__) && !defined(__MINGW64__) &&!defined(__CYGWIN__)
#include <sys/syscall.h>
#include <sys/time.h> //depr?
#include <sys/resource.h>
#elif defined(__MINGW32__) || defined(__MINGW64__)
#include <windows.h>
#endif

#define VERSION_MAJOR 0
#define VERSION_MINOR 7
#define VERSION_EXT "RC2 <experimental>"
#define GVERSION_MAJOR 0
#define GVERSION_MINOR 2
#define GVERSION_EXT "Alpha 2 <experimental>"

#define MAX_THREADS 64

/*********************************
* global variables, structs and extern functions
*********************************/

int collision_table_bits;
bool use_avxsse4;
bool use_sphlib;
bool use_gpu;
int gpu_ver;
std::vector<int> deviceList;
std::vector<CProtoshareProcessorGPU *> gpu_processors;
size_t thread_num_max;
static size_t fee_to_pay;
static size_t miner_id;
static boost::asio::ip::tcp::socket* socket_to_server;
static boost::posix_time::ptime t_start;
static std::map<int,unsigned long> statistics;
static bool running;
std::string pool_username;
std::string pool_password;
std::string pool_address;
std::string pool_port;

volatile uint64_t totalCollisionCount = 0;
volatile uint64_t totalShareCount = 0;

/**
 * don't know where to put it.
 */
void print256(const char* bfstr, uint32_t* v) {
	std::stringstream ss;
	for(ptrdiff_t i=7; i>=0; --i)
		ss << std::setw(8) << std::setfill('0') << std::hex << v[i];
    ss.flush();
    std::cout << bfstr << ": " << ss.str().c_str() << std::endl;
}


/*********************************
* class CBlockProviderGW to (incl. SUBMIT_BLOCK)
*********************************/

class CBlockProviderGW : public CBlockProvider {
public:

	CBlockProviderGW() : CBlockProvider(), nTime_offset(0), _block(NULL) {}

	virtual ~CBlockProviderGW() { /* TODO */ }

	virtual unsigned int GetAdjustedTimeWithOffset(unsigned int thread_id) {
		return nTime_offset + ((((unsigned int)time(NULL) + thread_num_max) / thread_num_max) * thread_num_max) + thread_id;
	}

	virtual blockHeader_t* getBlock(unsigned int thread_id, unsigned int last_time, unsigned int counter) {
		blockHeader_t* block = NULL;
		{
			boost::shared_lock<boost::shared_mutex> lock(_mutex_getwork);
			if (_block == NULL) return NULL;
			block = new blockHeader_t;
			memcpy(block, _block, 80+32+8);
		}		
		unsigned int new_time = GetAdjustedTimeWithOffset(thread_id);
		new_time += counter * thread_num_max;
		block->nTime = new_time;
		//std::cout << "[WORKER" << thread_id << "] block @ " << new_time << std::endl;
		return block;
	}
	
	virtual blockHeader_t* getOriginalBlock() {
		//boost::shared_lock<boost::shared_mutex> lock(_mutex_getwork);
		return _block;
	}
	
	virtual void setBlockTo(blockHeader_t* newblock) {
		blockHeader_t* old_block = NULL;
		{
			boost::unique_lock<boost::shared_mutex> lock(_mutex_getwork);
			old_block = _block;
			_block = newblock;
		}
		if (old_block != NULL) delete old_block;
	}

	void setBlocksFromData(unsigned char* data) {
		blockHeader_t* block = new blockHeader_t;
		memcpy(block, data, 80); //0-79
		block->birthdayA = 0;    //80-83
		block->birthdayB = 0;    //84-87
		memcpy(((unsigned char*)block)+88,data+80, 32);
		//
		unsigned int nTime_local = time(NULL);
		unsigned int nTime_server = block->nTime;
		nTime_offset = nTime_local > nTime_server ? 0 : (nTime_server-nTime_local);
		//
		setBlockTo(block);
	}

	void submitBlock(blockHeader_t *block, unsigned int thread_id) {
		if (socket_to_server != NULL) {
			blockHeader_t submitblock; //!
			memcpy((unsigned char*)&submitblock, (unsigned char*)block, 88);
			std::cout << "[WORKER] collision found: " << submitblock.birthdayA << " <-> " << submitblock.birthdayB << " #" << totalCollisionCount << " @ " << submitblock.nTime << " by " << thread_id << std::endl;
			boost::system::error_code submit_error = boost::asio::error::host_not_found;
			if (socket_to_server != NULL) boost::asio::write(*socket_to_server, boost::asio::buffer((unsigned char*)&submitblock, 88), boost::asio::transfer_all(), submit_error); //FaF
			//if (submit_error)
			//	std::cout << submit_error << " @ submit" << std::endl;
			if (!submit_error)
				++totalShareCount;
		}
	}

protected:
	unsigned int nTime_offset;
	boost::shared_mutex _mutex_getwork;
	blockHeader_t* _block;
};

/*********************************
* multi-threading
*********************************/

class CMasterThreadStub {
public:
  virtual void wait_for_master() = 0;
  virtual boost::shared_mutex& get_working_lock() = 0;
};


class CWorkerThread { // worker=miner
public:

	CWorkerThread(CMasterThreadStub *master, unsigned int id, CBlockProviderGW *bprovider)
		: _working_lock(NULL), _id(id), _master(master), _bprovider(bprovider), _thread(&CWorkerThread::run, this) {

			mintime = 0x3fffffff;
			totaltime = 0;
			num_runs = 0;
		}

	unsigned int mintime;
	unsigned int totaltime;
	unsigned int num_runs;
	

	void mineloop(SHAMODE shamode, int collisionTableBits) {
		unsigned int blockcnt = 0;
		blockHeader_t* thrblock = NULL;
		blockHeader_t* orgblock = NULL;
		CProtoshareProcessor * processor;
		if (shamode != GPU)
			processor = new CProtoshareProcessor(shamode, collisionTableBits, _id);
		else
			processor = gpu_processors[_id];

		while (running) {
			if (orgblock != _bprovider->getOriginalBlock()) {
				orgblock = _bprovider->getOriginalBlock();
				blockcnt = 0;
			}
			thrblock = _bprovider->getBlock(_id, thrblock == NULL ? 0 : thrblock->nTime, blockcnt);
			if (orgblock == _bprovider->getOriginalBlock()) {
				++blockcnt;
			}
			if (thrblock != NULL) {
			    struct timeval tv;
			    gettimeofday(&tv, NULL);

		    	processor->protoshares_process((blockHeader_t*)thrblock, (CBlockProvider*)_bprovider);

			    unsigned int begin_time = (tv.tv_sec * 1000 + tv.tv_usec / 1000);
			    gettimeofday(&tv, NULL);
			    unsigned int end_time = (tv.tv_sec * 1000 + tv.tv_usec / 1000);
			    unsigned int elapsed_time = end_time-begin_time;
			    if (mintime > elapsed_time) {
			    	mintime = elapsed_time;
			    }
			    totaltime += elapsed_time;
			    num_runs++;
			    double average_time = ((double)totaltime)/((double)num_runs);
#ifdef DEBUG
				std::cout << "Time Elapsed thread " << _id << ": "
						<< elapsed_time << " (min: " << mintime << " avg: "
						<< average_time <<")" << std::endl;
#endif
			} else
				boost::this_thread::sleep(boost::posix_time::seconds(1));
		}
	}
	
	void mineloop_start(SHAMODE shamode, int collisionTableBits) {
		mineloop(shamode, collisionTableBits);
	}

	void run() {
		std::cout << "[WORKER" << _id << "] Hello, World!" << std::endl;
		{
			//set low priority
#if defined(__GNUG__) && !defined(__MINGW32__) && !defined(__MINGW64__) && !defined(__CYGWIN__)
			pid_t tid = (pid_t) syscall (SYS_gettid);
			setpriority(PRIO_PROCESS, tid, -1);
#elif defined(__MINGW32__) || defined(__MINGW64__)
			HANDLE th = _thread.native_handle();
			if (!SetThreadPriority(th, THREAD_PRIORITY_LOWEST))
				std::cerr << "failed to set thread priority to low" << std::endl;
#endif
		}
		_master->wait_for_master();
		std::cout << "[WORKER" << _id << "] GoGoGo!" << std::endl;
		boost::this_thread::sleep(boost::posix_time::seconds(1));
		if (use_gpu) {
			mineloop_start(GPU, collision_table_bits); // <-- work loop
		}
		else if (use_avxsse4)
			mineloop_start(AVXSSE4, collision_table_bits); // <-- work loop
		else if (use_sphlib)
			mineloop_start(SPHLIB, collision_table_bits); // ^
		else
			mineloop_start(FIPS180_2, collision_table_bits); // ^
		std::cout << "[WORKER" << _id << "] Bye Bye!" << std::endl;
	}

	void work() { // called from within master thread
		_working_lock = new boost::shared_lock<boost::shared_mutex>(_master->get_working_lock());
	}

protected:
  boost::shared_lock<boost::shared_mutex> *_working_lock;
  unsigned int _id;
  CMasterThreadStub *_master;
  CBlockProviderGW  *_bprovider;
  boost::thread _thread;
};

class CMasterThread : public CMasterThreadStub {
public:

  CMasterThread(CBlockProviderGW *bprovider) : CMasterThreadStub(), _bprovider(bprovider) {}

  void run() {

	{
		boost::unique_lock<boost::shared_mutex> lock(_mutex_master);
		std::cout << "spawning " << thread_num_max << " worker thread(s)" << std::endl;

		for (unsigned int i = 0; i < thread_num_max; ++i) {
			CWorkerThread *worker = new CWorkerThread(this, i, _bprovider);
			worker->work();
		}
	}

    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service); //resolve dns
	//boost::asio::ip::tcp::resolver::query query("ptsmine.beeeeer.org", "1337");
	boost::asio::ip::tcp::resolver::query query(pool_address, pool_port);
    boost::asio::ip::tcp::resolver::iterator endpoint;
	boost::asio::ip::tcp::resolver::iterator end;
	boost::asio::ip::tcp::no_delay nd_option(true);
	boost::asio::socket_base::keep_alive ka_option(true);

	while (running) {
		endpoint = resolver.resolve(query);
		boost::scoped_ptr<boost::asio::ip::tcp::socket> socket;
		boost::system::error_code error_socket = boost::asio::error::host_not_found;
		while (error_socket && endpoint != end)
		{
			//socket->close();
			socket.reset(new boost::asio::ip::tcp::socket(io_service));
			boost::asio::ip::tcp::endpoint tcp_ep = *endpoint++;
			socket->connect(tcp_ep, error_socket);
			std::cout << "connecting to " << tcp_ep << std::endl;
		}
		socket->set_option(nd_option);
		socket->set_option(ka_option);

		if (error_socket) {
			std::cout << error_socket << std::endl;
			boost::this_thread::sleep(boost::posix_time::seconds(10));
			continue;
		} else {
			t_start = boost::posix_time::second_clock::local_time();
			totalCollisionCount = 0;
			totalShareCount = 0;
		}

		{ //send hello message
			char* hello = new char[pool_username.length()+/*v0.2/0.3=*/2+/*v0.4=*/20+/*v0.7=*/1+pool_password.length()];
			memcpy(hello+1, pool_username.c_str(), pool_username.length());
			*((unsigned char*)hello) = pool_username.length();
			*((unsigned char*)(hello+pool_username.length()+1)) = 0; //hi, i'm v0.4+
			*((unsigned char*)(hello+pool_username.length()+2)) = VERSION_MAJOR;
			*((unsigned char*)(hello+pool_username.length()+3)) = VERSION_MINOR;
			*((unsigned char*)(hello+pool_username.length()+4)) = thread_num_max;
			*((unsigned char*)(hello+pool_username.length()+5)) = fee_to_pay;
			*((unsigned short*)(hello+pool_username.length()+6)) = miner_id;
			*((unsigned int*)(hello+pool_username.length()+8)) = 0;
			*((unsigned int*)(hello+pool_username.length()+12)) = 0;
			*((unsigned int*)(hello+pool_username.length()+16)) = 0;
			*((unsigned char*)(hello+pool_username.length()+20)) = pool_password.length();
			memcpy(hello+pool_username.length()+21, pool_password.c_str(), pool_password.length());
			*((unsigned short*)(hello+pool_username.length()+21+pool_password.length())) = 0; //EXTENSIONS
			boost::system::error_code error;
			socket->write_some(boost::asio::buffer(hello, pool_username.length()+2+20+1+pool_password.length()), error);
			//if (error)
			//	std::cout << error << " @ write_some_hello" << std::endl;
			delete[] hello;
		}

		socket_to_server = socket.get(); //TODO: lock/mutex

		int reject_counter = 0;
		bool done = false;
		while (!done) {
			int type = -1;
			{ //get the data header
				unsigned char buf = 0; //get header
				boost::system::error_code error;
				size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(&buf, 1), boost::asio::transfer_all(), error);
				if (error == boost::asio::error::eof)
					break; // Connection closed cleanly by peer.
				else if (error) {
					//std::cout << error << " @ read_some1" << std::endl;
					break;
				}
				type = buf;
				if (len != 1)
					std::cout << "error on read1: " << len << " should be " << 1 << std::endl;
			}

			switch (type) {
				case 0: {
					size_t buf_size = 112; //*thread_num_max;
					unsigned char* buf = new unsigned char[buf_size]; //get header
					boost::system::error_code error;
					size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(buf, buf_size), boost::asio::transfer_all(), error);
					if (error == boost::asio::error::eof) {
						done = true;
						break; // Connection closed cleanly by peer.
					} else if (error) {
						//std::cout << error << " @ read2a" << std::endl;
						done = true;
						break;
					}
					if (len == buf_size) {
						_bprovider->setBlocksFromData(buf);
						std::cout << "[MASTER] work received - ";
						if (_bprovider->getOriginalBlock() != NULL) print256("sharetarget", (uint32_t*)(_bprovider->getOriginalBlock()->targetShare));
						else std::cout << "<NULL>" << std::endl;
					} else
						std::cout << "error on read2a: " << len << " should be " << buf_size << std::endl;
					delete[] buf;
				} break;
				case 1: {
					size_t buf_size = 4;
					int buf; //get header
					boost::system::error_code error;
					size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(&buf, buf_size), boost::asio::transfer_all(), error);
					if (error == boost::asio::error::eof) {
						done = true;
						break; // Connection closed cleanly by peer.
					} else if (error) {
						//std::cout << error << " @ read2b" << std::endl;
						done = true;
						break;
					}
					if (len == buf_size) {
						int retval = buf > 1000 ? 1 : buf;
						std::cout << "[MASTER] submitted share -> " <<
							(retval == 0 ? "REJECTED" : retval < 0 ? "STALE" : retval ==
							1 ? "BLOCK" : "SHARE") << std::endl;
						if (retval > 0)
							reject_counter = 0;
						else
							reject_counter++;
						if (reject_counter >= 3) {
							std::cout << "too many rejects (3) in a row, forcing reconnect." << std::endl;
							socket->close();
							done = true;
						}
						{
							std::map<int,unsigned long>::iterator it = statistics.find(retval);
							if (it == statistics.end())
								statistics.insert(std::pair<int,unsigned long>(retval,1));
							else
								statistics[retval]++;
							//stats_running();
						}
					} else
						std::cout << "error on read2b: " << len << " should be " << buf_size << std::endl;
				} break;
				case 2: {
					//PING-PONG EVENT, nothing to do
				} break;
				default: {
					//std::cout << "unknown header type = " << type << std::endl;
				}
			}
			stats_running();
		}

		_bprovider->setBlockTo(NULL);
		socket_to_server = NULL; //TODO: lock/mutex		
		std::cout << "no connection to the server, reconnecting in 10 seconds" << std::endl;
		boost::this_thread::sleep(boost::posix_time::seconds(10));
	}
  }

  ~CMasterThread() {}

  void wait_for_master() {
    boost::shared_lock<boost::shared_mutex> lock(_mutex_master);
  }

  boost::shared_mutex& get_working_lock() {
    return _mutex_working;
  }

private:

  void wait_for_workers() {
    boost::unique_lock<boost::shared_mutex> lock(_mutex_working);
  }

  CBlockProviderGW  *_bprovider;

  boost::shared_mutex _mutex_master;
  boost::shared_mutex _mutex_working;

	// Provides real time stats
	void stats_running() {
		if (!running) return;
		std::cout << std::fixed;
		std::cout << std::setprecision(1);
		boost::posix_time::ptime t_end = boost::posix_time::second_clock::local_time();
		unsigned long rejects = 0;
		unsigned long stale = 0;
		unsigned long valid = 0;
		unsigned long blocks = 0;
		for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it) {
			if (it->first < 0) stale += it->second;
			if (it->first == 0) rejects = it->second;
			if (it->first == 1) blocks = it->second;
			if (it->first > 1) valid += it->second;
		}
		std::cout << "[STATS] " << t_end << " | ";
		if ((t_end - t_start).total_seconds() > 0) {
			std::cout << static_cast<double>(totalCollisionCount) / (static_cast<double>((t_end - t_start).total_seconds()) / 60.0) << " c/m | ";
			std::cout << static_cast<double>(totalShareCount) / (static_cast<double>((t_end - t_start).total_seconds()) / 60.0) << " sh/m | ";			
		}
		if (valid+blocks+rejects+stale > 0) {
			std::cout << "VL: " << valid+blocks << " (" << (static_cast<double>(valid+blocks) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
			std::cout << "RJ: " << rejects << " (" << (static_cast<double>(rejects) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
			std::cout << "ST: " << stale << " (" << (static_cast<double>(stale) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
		} else {
			std::cout <<  "VL: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "RJ: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "ST: " << 0 << " (" << 0.0 << "%)" << std::endl;
		}
	}
};

/*********************************
* exit / end / shutdown
*********************************/

void exit_handler() {
	//cleanup for not-retarded OS
	if (socket_to_server != NULL) {
		socket_to_server->close();
		socket_to_server = NULL;
	}
	running = false;
}

#if defined(__MINGW32__) || defined(__MINGW64__)

//#define WIN32_LEAN_AND_MEAN
//#include <windows.h>

BOOL WINAPI ctrl_handler(DWORD dwCtrlType) {
	//'special' cleanup for windows
	switch(dwCtrlType) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT: {
			if (socket_to_server != NULL) {
				socket_to_server->close();
				socket_to_server = NULL;
			}
			running = false;
		} break;
		default: break;
	}
	return FALSE;
}

#elif defined(__GNUG__) && !defined(__APPLE__)

static sighandler_t set_signal_handler (int signum, sighandler_t signalhandler) {
   struct sigaction new_sig, old_sig;
   new_sig.sa_handler = signalhandler;
   sigemptyset (&new_sig.sa_mask);
   new_sig.sa_flags = SA_RESTART;
   if (sigaction (signum, &new_sig, &old_sig) < 0)
      return SIG_ERR;
   return old_sig.sa_handler;
}

void ctrl_handler(int signum) {
	exit(1);
}

#endif

// get args
std::string getArgStr(int argc, char **argv, std::string name, std::string def) {
	for(int i = 0; i < argc-1; i++) {
		if (name == std::string(argv[i])) {
			return std::string(argv[i+1]);
		}
	}
	return def;
}

int getArgInt(int argc, char **argv, std::string name, int def) {
	for(int i = 0; i < argc-1; i++) {
		if (name == std::string(argv[i])) {
			return atoi(argv[i+1]);
		}
	}
	return def;
}

bool getArgBoolean(int argc, char **argv, std::string name) {
	for(int i = 0; i < argc; i++) {
		if (name == std::string(argv[i])) {
			return true;
		}
	}
	return false;
}

std::vector<int> getArgVector(int argc, char **argv, std::string name) {
	std::vector<int> ret;
	for(int i = 0; i < argc-1; i++) {
		if (name == std::string(argv[i])) {
			std::string list = std::string(argv[i+1]);
			std::string delimiter = ",";
			size_t pos = 0;
			while ((pos = list.find(delimiter)) != std::string::npos) {
				std::string token = list.substr(0, pos);
				ret.push_back(atoi(token.c_str()));
			    list.erase(0, pos + delimiter.length());
			}
			ret.push_back(atoi(list.c_str()));
			break;
		}
	}
	return ret;
}

void print_help(const char* _exec) {
	std::cerr << "usage: " << _exec << " -u <payout-address/username> [-p password] [-t <threads-to-use>] [-m <memory-option>] [-a <mode>] [-o <server>] [-q port] [-device x,y,z]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "defaults: -u '' -p x -t 1 -m 27 -a auto -o ptsmine.beeeeer.org -q 1337 -device 0" << std::endl;
	std::cerr << std::endl;
	std::cerr << "memory-option: integer value - memory usage" << std::endl;
	std::cerr << "\t\t20 -->    4 MB per thread (not recommended)" << std::endl;
	std::cerr << "\t\t21 -->    8 MB per thread (not recommended)" << std::endl;
	std::cerr << "\t\t22 -->   16 MB per thread (not recommended)" << std::endl;
	std::cerr << "\t\t23 -->   32 MB per thread (not recommended)" << std::endl;
	std::cerr << "\t\t24 -->   64 MB per thread (not recommended)" << std::endl;
	std::cerr << "\t\t25 -->  128 MB per thread" << std::endl;
	std::cerr << "\t\t26 -->  256 MB per thread" << std::endl;
	std::cerr << "\t\t27 -->  512 MB per thread (default)" << std::endl;
	std::cerr << "\t\t28 --> 1024 MB per thread" << std::endl;
	std::cerr << "\t\t29 --> 2048 MB per thread" << std::endl;
	std::cerr << "\t\t30 --> 4096 MB per thread" << std::endl;
	std::cerr << std::endl;
	std::cerr << "mode: string - mining implementation" << std::endl;
	std::cerr << "\t\tavx --> use AVX (Intel optimized)" << std::endl;
	std::cerr << "\t\tsse4 --> use SSE4 (Intel optimized)" << std::endl;
	std::cerr << "\t\tsph --> use SPHLIB" << std::endl;
	std::cerr << "\t\tgpu --> use GPU (remember to specify the devices with -device)" << std::endl;
	std::cerr << std::endl;
	std::cerr << "examples:" << std::endl;
	std::cerr << "> " << _exec << " -u PkyeQNn1yGV5psGeZ4sDu6nz2vWHTujf4h -t 4 -m 25 -a sse4" << std::endl;
	std::cerr << "> " << _exec << " -u PkyeQNn1yGV5psGeZ4sDu6nz2vWHTujf4h -device 1,2,5 -m 28 -a gpu" << std::endl;
	std::cerr << std::endl;
	std::cerr << "To list available GPU devices:" << std::endl;
	std::cerr << "> " << _exec << " -list-devices" << std::endl;
}

/*********************************
* main - this is where it begins
*********************************/
int main(int argc, char **argv)
{
	std::cout << "*******************************************************" << std::endl;
	std::cout << "*** GPU PTS miner by girino v" << GVERSION_MAJOR << "." << GVERSION_MINOR << " " << GVERSION_EXT << std::endl;
	std::cout << "*** based on Pts Pool Miner v" << VERSION_MAJOR << "." << VERSION_MINOR << " " << VERSION_EXT << std::endl;
	std::cout << "*** by xolokram/TB - www.beeeeer.org - glhf" << std::endl;
	std::cout << "*** " << std::endl;
	std::cout << "*** GPU support and performance improvements by girino " << std::endl;
	std::cout << "***    if you like, donate:  " << std::endl;
	std::cout << "***    PTS: PkyeQNn1yGV5psGeZ4sDu6nz2vWHTujf4h  " << std::endl;
	std::cout << "***    BTC: 1GiRiNoKznfGbt8bkU1Ley85TgVV7ZTXce  " << std::endl;
	std::cout << "*** thanks to wjchen for SSE4 improvements." << std::endl;
	std::cout << "***" << std::endl;
	std::cout << "*** press CTRL+C to exit" << std::endl;
	std::cout << "*******************************************************" << std::endl;
	
	// init everything:
	socket_to_server = NULL;
	thread_num_max = getArgInt(argc, argv, "-t", 1); // what about boost's hardware_concurrency() ?
	collision_table_bits = getArgInt(argc, argv, "-m", 27);
	fee_to_pay = 0; //GetArg("-poolfee", 3);
	miner_id = 0; //GetArg("-minerid", 0);
	pool_username = getArgStr(argc, argv, "-u", "");
	pool_password = getArgStr(argc, argv, "-p", "x");
	pool_address = getArgStr(argc, argv, "-o", "ptsmine.beeeeer.org");
	pool_port = getArgStr(argc, argv, "-q", "1337");
	std::string mode_param = getArgStr(argc, argv, "-a", "auto");
	deviceList = getArgVector(argc, argv, "-device");
	bool list_devices_and_quit = getArgBoolean(argc, argv, "-list-devices");

	if (list_devices_and_quit) {
		printf("Available devices:\n");
		OpenCLMain::getInstance().listDevices();
		return EXIT_SUCCESS;
	}

	if (pool_username == "")
	{
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	use_avxsse4 = false;
	use_sphlib = true;
	if (mode_param == "avx") {
		Init_SHA512_avx();
		use_avxsse4 = true;
		std::cout << "using AVX" << std::endl;
	} else if (mode_param == "sse4") {
		Init_SHA512_sse4();
		use_avxsse4 = true;
		std::cout << "using SSE4" << std::endl;
	} else if (mode_param == "sph") {
		std::cout << "using SPHLIB" << std::endl;
	} else if (mode_param == "fips") {
		std::cout << "using FIPS 180-2" << std::endl;
		use_sphlib = false;
	} else if (mode_param.substr(0, 3) == "gpu") {
		std::cout << "using GPU" << std::endl;
		use_gpu = true;
		use_sphlib = true;
		gpu_ver = 4;
		if (mode_param == "gpuv2") gpu_ver = 2;
		else if (mode_param == "gpuv3") gpu_ver = 3;
		else if (mode_param == "gpuv4") gpu_ver = 4;
		else if (mode_param == "gpuv5") gpu_ver = 5;
	} else {
#ifdef	__x86_64__
		std::cout << "**" << "SSE4/AVX auto-detection" << std::endl;
		processor_info_t proc_info;
		cpuid_basic_identify(&proc_info);
		if (proc_info.proc_type == PROC_X64_INTEL || proc_info.proc_type == PROC_X64_AMD) {
			if (proc_info.avx_level > 0) {
				Init_SHA512_avx();
				use_avxsse4 = true;
				std::cout << "using AVX" << std::endl;
			} else if (proc_info.sse_level >= 4) {
				Init_SHA512_sse4();
				use_avxsse4 = true;
				std::cout << "using SSE4" << std::endl;
			} else
				std::cout << "using SPHLIB (no avx/sse4)" << std::endl;
		} else
			std::cout << "using SPHLIB (unsupported arch)" << std::endl;
#else
		//TODO: make this compatible with 32bit systems
		std::cout << "**** >>> WARNING" << std::endl;
		std::cout << "**" << std::endl;
		std::cout << "**" << "SSE4/AVX auto-detection not available on your machine" << std::endl;
		std::cout << "**" << "please enable SSE4 or AVX manually" << std::endl;
		std::cout << "**" << std::endl;
		std::cout << "**** >>> WARNING" << std::endl;
#endif
	}

	if (use_gpu) {
		printf("Available devices:\n");
		OpenCLMain::getInstance().listDevices();
		if (deviceList.empty()) {
			for (int i = 0; i < thread_num_max; i++) {
				deviceList.push_back(i);
			}
		} else {
			thread_num_max = deviceList.size();
		}
		std::cout << "Adjusting num threads to match device list: " << thread_num_max << std::endl;
	}

	t_start = boost::posix_time::second_clock::local_time();
	running = true;

#if defined(__MINGW32__) || defined(__MINGW64__)
	SetConsoleCtrlHandler(ctrl_handler, TRUE);
#elif defined(__GNUG__) && !defined(__APPLE__)
	set_signal_handler(SIGINT, ctrl_handler);
#endif

	const int atexit_res = std::atexit(exit_handler);
	if (atexit_res != 0)
		std::cerr << "atexit registration failed, shutdown will be dirty!" << std::endl;

	if (collision_table_bits < 20 || collision_table_bits > 30)
	{
		std::cerr << "unsupported memory option, choose a value between 20 and 31" << std::endl;
		return EXIT_FAILURE;
	}

	if (thread_num_max == 0 || thread_num_max > MAX_THREADS)
	{
		std::cerr << "usage: " << "current maximum supported number of threads = " << MAX_THREADS << std::endl;
		return EXIT_FAILURE;
	}

	{
		unsigned char pw[32];
		//SPH
		sph_sha256_context c256_sph;		
		sph_sha256_init(&c256_sph);
		sph_sha256(&c256_sph, (unsigned char*)pool_password.c_str(), pool_password.size());
		sph_sha256_close(&c256_sph, pw);
		//print256("sph",(uint32_t*)pw);
		//
		std::stringstream ss;
		ss << std::setw(5) << std::setfill('0') << std::hex << (pw[0] ^ pw[5] ^ pw[2] ^ pw[7]) << (pw[4] ^ pw[1] ^ pw[6] ^ pw[3]);
		pool_password = ss.str();	
	}

	// preinits GPU processors
	if (use_gpu) {
		printf("Initializing GPU...\n");
		for (int i = 0; i < deviceList.size(); i++) {
			printf("Initing device %d.\n", i);
			gpu_processors.push_back(new CProtoshareProcessorGPU(GPU, gpu_ver, collision_table_bits, i, deviceList[i]));
			printf("Device %d Inited.\n", i);
		}
		printf("All GPUs Initialized...\n");
	}

	// ok, start mining:
	CBlockProviderGW* bprovider = new CBlockProviderGW();
	CMasterThread *mt = new CMasterThread(bprovider);
	mt->run();

	// end:
	return EXIT_SUCCESS;
}

/*********************************
* and this is where it ends
*********************************/
