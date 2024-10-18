#ifndef KANGAROOH
#define KANGAROOH

#ifdef WIN64
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#else
typedef int SOCKET;
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
#endif

#include <string>
#include <vector>
#include "SECPK1/SECP256k1.h"
#include "HashTable.h"
#include "SECPK1/IntGroup.h"
#include "GPU/GPUEngine.h"
#include <unordered_map>
#include <bitset>
#include <sys/resource.h>
#ifdef WIN64
typedef HANDLE THREAD_HANDLE;
#define LOCK(mutex) WaitForSingleObject(mutex,INFINITE);
#define UNLOCK(mutex) ReleaseMutex(mutex);
#else
typedef pthread_t THREAD_HANDLE;
#define LOCK(mutex)  pthread_mutex_lock(&(mutex));
#define UNLOCK(mutex) pthread_mutex_unlock(&(mutex));
#endif

class Kangaroo;

// Input thread parameters
typedef struct {
  Kangaroo *obj;
  int  threadId;
  bool isRunning;
  bool hasStarted;
  bool isWaiting;
  uint64_t nbKangaroo;
#ifdef WITHGPU
  int  gridSizeX;
  int  gridSizeY;
  int  gpuId;
#endif
  Int *px; // Kangaroo position
  Int *py; // Kangaroo position
  Int *distance; // Travelled distance
#ifdef USE_SYMMETRY
  uint64_t *symClass; // Last jump
#endif
  uint32_t hStart;
  uint32_t hStop;
  char *part1Name;
  char *part2Name;
} TH_PARAM;

struct IntHash {
    std::size_t operator()(const Int& k) const {
        Int temp = k;
        return std::hash<std::string>()(temp.GetBase16());
    }
};

struct IntEqual {
    bool operator()(const Int& lhs, const Int& rhs) const {
        Int temp_lhs = lhs;
        Int temp_rhs = rhs;
        return temp_lhs.GetBase16() == temp_rhs.GetBase16();
    }
};
// DP transfered over the network
typedef struct {
  uint32_t kIdx;
  int256_t x;
  int256_t d;
} DP;

typedef struct {
  uint32_t header;
  uint32_t nbDP;
  uint32_t threadId;
  uint32_t processId;
  uint32_t gpuId;
} DPHEADER;

// DP cache
typedef struct {
  uint32_t nbDP;
  DP *dp;
} DP_CACHE;

// Work file type
#define HEADW  0xFA6A8001  // Full work file
#define HEADK  0xFA6A8002  // Kangaroo only file
#define HEADKS 0xFA6A8003  // Compressed Kangaroo only file

// Number of Hash entry per partition
#define H_PER_PART (HASH_SIZE / MERGE_PART)

class Kangaroo {
public:
  Kangaroo(Secp256K1 *secp, int32_t initDPSize, bool useGpu, std::string &workFile, std::string &iWorkFile, 
           uint32_t savePeriod, bool saveKangaroo, double maxStep, int wtimeout, int ntimeout, 
           std::string outputFile, bool splitWorkfile);

  void Run(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize);
  bool ParseConfigFile(std::string &fileName);
  bool LoadWork(std::string &fileName);
  void Check(std::vector<int> gpuId, std::vector<int> gridSize);
  void MergeDir(std::string& dirname, std::string& dest);
  bool MergeWork(std::string &file1, std::string &file2, std::string &dest, bool printStat=true);
  void WorkInfo(std::string &fileName);
  bool MergeWorkPart(std::string& file1, std::string& file2, bool printStat);
  bool MergeWorkPartPart(std::string& part1Name, std::string& part2Name);
  static void CreateEmptyPartWork(std::string& partName);
  void CheckWorkFile(int nbCore, std::string& fileName);
  void CheckPartition(int nbCore, std::string& partName);
  bool FillEmptyPartFromFile(std::string& partName, std::string& fileName, bool printStat);
  // Threaded procedures
  void SolveKeyCPU(TH_PARAM *p);
  void SolveKeyGPU(TH_PARAM *p);
  bool HandleRequest(TH_PARAM *p);
  bool MergePartition(TH_PARAM* p);
  bool CheckPartition(TH_PARAM* p);
  bool CheckWorkFile(TH_PARAM* p);
  void RemoveConnectedKangaroo(uint64_t nb);
  double calculateDeviation(double* distances, int size);
private:
  bool IsDP(Int *x);
  void SetDP(int size);
  void CreateHerd(int nbKangaroo, Int *px, Int *py, Int *d, int firstType, bool lock=true);
  void CreateJumpTable();
  void AddToTable(Point &p);
  bool AddToTable(uint64_t h, int256_t *x, int256_t *d);
  bool AddToTable(int256_t *x, int256_t *d, uint32_t kType);
  bool AddToTable(uint64_t h, int256_t *x, int256_t *d, uint32_t kType);
  bool AddToTable(Int *pos, Int *dist, uint32_t kType);
  bool CheckKey(Int d1, Int d2, uint8_t type);
  bool CollisionCheck(Int* d1, uint32_t type1, Int* d2, uint32_t type2);
  void ComputeExpected(double dp, double *op, double *ram, double* overHead = NULL);
  void InitRange();
  void InitSearchKey();
  std::string GetTimeStr(double s);
  bool Output(Int* pk, char sInfo, int sType);

  // Backup stuff
  void SaveWork(std::string fileName, FILE *f, int type, uint64_t totalCount, double totalTime);
  void SaveWork(uint64_t totalCount, double totalTime, TH_PARAM *threads, int nbThread);
  void FetchWalks(uint64_t nbWalk, Int *x, Int *y, Int *d);
  void FetchWalks(uint64_t nbWalk, std::vector<int256_t>& kangs, Int* x, Int* y, Int* d);
  void FectchKangaroos(TH_PARAM *threads);
  FILE *ReadHeader(std::string fileName, uint32_t *version, int type);
  bool SaveHeader(std::string fileName, FILE* f, int type, uint64_t totalCount, double totalTime);
  int FSeek(FILE *stream, uint64_t pos);
  uint64_t FTell(FILE *stream);
  int IsDir(std::string dirName);
  bool IsEmpty(std::string fileName);
  static std::string GetPartName(std::string& partName, int i, bool tmpPart);
  static FILE* OpenPart(std::string& partName, char* mode, int i, bool tmpPart=false);
  uint32_t CheckHash(uint32_t h, uint32_t nbItem, HashTable* hT, FILE* f);
#ifdef WIN64
  HANDLE ghMutex;
  HANDLE saveMutex;
  THREAD_HANDLE LaunchThread(LPTHREAD_START_ROUTINE func, TH_PARAM *p);
#else
  pthread_mutex_t  ghMutex;
  pthread_mutex_t  saveMutex;
  THREAD_HANDLE LaunchThread(void *(*func) (void *), TH_PARAM *p);
#endif

  void JoinThreads(THREAD_HANDLE *handles, int nbThread);
  void FreeHandles(THREAD_HANDLE *handles, int nbThread);
  void Process(TH_PARAM *params, std::string unit);
  uint64_t getCPUCount();
  uint64_t getGPUCount();
  bool isAlive(TH_PARAM *p);
  bool hasStarted(TH_PARAM *p);
  bool isWaiting(TH_PARAM *p);

  Secp256K1 *secp;
  HashTable hashTable;
  uint64_t counters[256];
  int  nbCPUThread;
  int  nbGPUThread;
  double startTime;

  // Range
  int rangePower;
  Int rangeStart;
  Int rangeEnd;
  Int rangeWidth;
  Int rangeWidthDiv2;
  Int rangeWidthDiv4;
  Int rangeWidthDiv8;
  int256_t dMask;
  uint32_t dpSize;
  int32_t initDPSize;
  uint64_t collisionInSameHerd;
  std::vector<Point> keysToSearch;
  Point keyToSearch;
  Point keyToSearchNeg;
  uint32_t keyIdx;
  bool endOfSearch;
  bool useGpu;
  double expectedNbOp;
  double expectedMem;
  double maxStep;
  uint64_t totalRW;
  Int jumpDistance[NB_JUMP];
  Int jumpPointx[NB_JUMP];
  Int jumpPointy[NB_JUMP];
  int CPU_GRP_SIZE;

  // Backup stuff
  std::string outputFile;
  FILE *fRead;
  uint64_t offsetCount;
  double offsetTime;
  int64_t nbLoadedWalk;
  std::string workFile;
  std::string inputFile;
  int  saveWorkPeriod;
  bool saveRequest;
  bool saveKangaroo;
  int wtimeout;
  int ntimeout;
  bool splitWorkfile;

};

#endif // KANGAROOH
