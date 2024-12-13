#include <string.h>
#include <random>
#include <fstream>
#include "Kangaroo.h"
#include "SECPK1/IntGroup.h"
#include "Timer.h"
#define _USE_MATH_DEFINES
#include <math.h>
#include <algorithm>
#include <memory>
#ifndef WIN64
#include <pthread.h>
#endif
#include <unordered_map>
#include <bitset>
#include <vector>
#include <string>
#include <functional>
#include "SECPK1/Point.h" 
#include <chrono>

using namespace std;

#define safe_delete_array(x) \
  if (x) {                   \
    delete[] x;              \
    x = NULL;                \
  }

const int BLOOM_SIZE = 1000000;

std::unordered_map<std::string, Point> hashTable;
std::bitset<BLOOM_SIZE> bloomFilter;

std::string HashPoint(const Point &p) {
    Int tempX = p.x;
    Int tempY = p.y;
    std::string combined = tempX.GetBase16() + tempY.GetBase16();
    std::hash<std::string> hash_fn;
    return std::to_string(hash_fn(combined));
}

void Kangaroo::AddToTable(Point &p) {
    std::string hash = HashPoint(p);
    size_t hashValue = std::hash<std::string>{}(hash);
    bloomFilter[hashValue % BLOOM_SIZE] = 1;
    Int x, d;
    hashTable.Add(&x, &d, 0);
}

bool CheckCollision(Point &p) {
    std::string hash = HashPoint(p);
    size_t hashValue = std::hash<std::string>{}(hash);
    if (bloomFilter[hashValue % BLOOM_SIZE] == 0) {
        return false;
    }
    return hashTable.find(hash) != hashTable.end();
}

Kangaroo::Kangaroo(Secp256K1 *secp, int32_t initDPSize, bool useGpu, std::string &workFile, 
                   std::string &iWorkFile, uint32_t savePeriod, bool saveKangaroo, double maxStep, 
                   int wtimeout, int ntimeout, std::string outputFile, bool splitWorkfile) {
    this->secp = secp;
    this->initDPSize = initDPSize;
    this->useGpu = useGpu;
    this->offsetCount = 0;
    this->offsetTime = 0.0;
    this->workFile = workFile;
    this->saveWorkPeriod = savePeriod;
    this->inputFile = iWorkFile;
    this->nbLoadedWalk = 0;
    this->saveKangaroo = saveKangaroo;
    this->fRead = NULL;
    this->maxStep = maxStep;
    this->wtimeout = wtimeout;
    this->ntimeout = ntimeout;
    this->outputFile = outputFile;
    this->endOfSearch = false;
    this->saveRequest = false;
    this->totalRW = 0;
    this->collisionInSameHerd = 0;
    this->keyIdx = 0;
    this->splitWorkfile = splitWorkfile;
    CPU_GRP_SIZE = 1024;
#ifdef WIN64
    ghMutex = CreateMutex(NULL, FALSE, NULL);
    saveMutex = CreateMutex(NULL, FALSE, NULL);
#else
    pthread_mutex_init(&ghMutex, NULL);
    pthread_mutex_init(&saveMutex, NULL);
    signal(SIGPIPE, SIG_IGN);
#endif
    bloomFilter.reset();
    hashTable.Reset(); 
}

bool Kangaroo::ParseConfigFile(std::string &fileName) {
  FILE *fp = fopen(fileName.c_str(), "rb");
  if (fp == NULL) {
    ::printf("[+] Error: Cannot open %s %s\n", fileName.c_str(), strerror(errno));
    return false;
  }
  fclose(fp);

  vector<string> lines;
  int nbLine = 0;
  string line;
  ifstream inFile(fileName);
  while (getline(inFile, line)) {
    int l = (int)line.length() - 1;
    while (l >= 0 && isspace(line.at(l))) {
      line.pop_back();
      l--;
    }
    if (line.length() > 0) {
      lines.push_back(line);
      nbLine++;
    }
  }

  if (lines.size() < 3) {
    ::printf("[+] Error: %s not enough arguments\n", fileName.c_str());
    return false;
  }

  rangeStart.SetBase16((char *)lines[0].c_str());
  rangeEnd.SetBase16((char *)lines[1].c_str());

  for (int i = 2; i < (int)lines.size(); i++) {
    Point p;
    bool isCompressed;
    if (!secp->ParsePublicKeyHex(lines[i], p, isCompressed)) {
      ::printf("[+] %s, error line %d: %s\n", fileName.c_str(), i, lines[i].c_str());
      return false;
    }
    if (CheckCollision(p)) {
      // Handle collision
      ::printf("[+] Collision detected for key: %s\n", lines[i].c_str());
    } else {
      AddToTable(p);
      keysToSearch.push_back(p);
    }
  }

  ::printf("[+] Start:%s\n", rangeStart.GetBase16().c_str());
  ::printf("[+] Stop :%s\n", rangeEnd.GetBase16().c_str());
  ::printf("[+] Keys :%d\n", (int)keysToSearch.size());
  return true;
}

bool Kangaroo::IsDP(Int *x) {
  return ((x->bits64[3] & dMask.i64[3]) == 0) &&
         ((x->bits64[2] & dMask.i64[2]) == 0) &&
         ((x->bits64[1] & dMask.i64[1]) == 0) &&
         ((x->bits64[0] & dMask.i64[0]) == 0);
}

void Kangaroo::SetDP(int size) {
    dpSize = (size > 0) ? size : std::max(2, (rangePower + 8) / 9);
    if (dpSize > 256) dpSize = 256;

    dMask.i64[0] = 0;
    dMask.i64[1] = 0;
    dMask.i64[2] = 0;
    dMask.i64[3] = 0;

    if (dpSize > 0) {
        for (int i = 0; i < dpSize; i += 64) {
            int end = (i + 64 > dpSize) ? (dpSize - 1) % 64 : 63;
            uint64_t mask = ((1ULL << end) - 1) << 1 | 1ULL;
            dMask.i64[(int)(i / 64)] = mask;
        }
    }

#ifdef WIN64
    ::printf("[+] DP size: %d [0x%016I64X%016I64%016I64X%016I64X]\n", dpSize,
             dMask.i64[3], dMask.i64[2], dMask.i64[1], dMask.i64[0]);
#else
    ::printf("[+] DP size: %d [0x%" PRIx64 "%" PRIx64 "%" PRIx64 "%" PRIx64 "]\n",
             dpSize, dMask.i64[3], dMask.i64[2], dMask.i64[1], dMask.i64[0]);
#endif
}

bool Kangaroo::Output(Int *pk, char sInfo, int sType) {
  FILE *f = stdout;
  bool needToClose = false;
  if (outputFile.length() > 0) {
    f = fopen(outputFile.c_str(), "a");
    if (f == NULL) {
      printf("[+] Cannot open %s for writing\n", outputFile.c_str());
      f = stdout;
    } else {
      needToClose = true;
    }
  }
  if (!needToClose) ::printf("\n");

  Point PR = secp->ComputePublicKey(pk);
  ::fprintf(f, "Key#%2d [%d%c]Pub: 0x%s \n", keyIdx, sType, sInfo,
            secp->GetPublicKeyHex(true, keysToSearch[keyIdx]).c_str());
  if (PR.equals(keysToSearch[keyIdx])) {
    ::fprintf(f, "Priv: 0x%s \n", pk->GetBase16().c_str());
  } else {
    ::fprintf(f, "Failed !\n");
    if (needToClose) fclose(f);
    return false;
  }
  if (needToClose) fclose(f);
  return true;
}

bool Kangaroo::CheckKey(Int d1, Int d2, uint8_t type) {
  
  if (type & 0x1) d1.ModNegK1order();
  if (type & 0x2) d2.ModNegK1order();
  Int pk(&d1);
  pk.ModAddK1order(&d2);
  Point P = secp->ComputePublicKey(&pk);
  if (P.equals(keyToSearch)) {
    
#ifdef USE_SYMMETRY
    pk.ModAddK1order(&rangeWidthDiv2);
#endif
    pk.ModAddK1order(&rangeStart);
    return Output(&pk, 'N', type);
  }
  if (P.equals(keyToSearchNeg)) {
    
    pk.ModNegK1order();
#ifdef USE_SYMMETRY
    pk.ModAddK1order(&rangeWidthDiv2);
#endif
    pk.ModAddK1order(&rangeStart);
    return Output(&pk, 'S', type);
  }
  return false;
}

bool Kangaroo::CollisionCheck(Int *d1, uint32_t type1, Int *d2, uint32_t type2) {
  if (type1 == type2) {
    
    return false;
  } else {
    Int Td;
    Int Wd;
    if (type1 == TAME) {
      Td.Set(d1);
      Wd.Set(d2);
    } else {
      Td.Set(d2);
      Wd.Set(d1);
    }
    endOfSearch = CheckKey(Td, Wd, 0) || CheckKey(Td, Wd, 1) ||
                  CheckKey(Td, Wd, 2) || CheckKey(Td, Wd, 3);
    if (!endOfSearch) {
      
      return false;
    }
  }
  return true;
}

bool Kangaroo::AddToTable(Int *pos, Int *dist, uint32_t kType) {
  int addStatus = hashTable.Add(pos, dist, kType);
  if (addStatus == ADD_COLLISION)
    return CollisionCheck(&hashTable.kDist, hashTable.kType, dist, kType);
  return addStatus == ADD_OK;
}

bool Kangaroo::AddToTable(int256_t *x, int256_t *d, uint32_t kType) {
  int addStatus = hashTable.Add(x, d, kType);
  if (addStatus == ADD_COLLISION) {
    Int dist;
    HashTable::toInt(d, &dist);
    return CollisionCheck(&hashTable.kDist, hashTable.kType, &dist, kType);
  }
  return addStatus == ADD_OK;
}

void Kangaroo::SolveKeyCPU(TH_PARAM *ph) {
  vector<ITEM> dps;
  double lastSent = 0;
  int thId = ph->threadId;
  ph->nbKangaroo = CPU_GRP_SIZE;

#ifdef USE_SYMMETRY
  ph->symClass = new uint64_t[CPU_GRP_SIZE];
  for (int i = 0; i < CPU_GRP_SIZE; i++) ph->symClass[i] = 0;
#endif

  IntGroup *grp = new IntGroup(CPU_GRP_SIZE);
  Int *dx = new Int[CPU_GRP_SIZE];
  if (ph->px == NULL) {
    ph->px = new Int[CPU_GRP_SIZE];
    ph->py = new Int[CPU_GRP_SIZE];
    ph->distance = new Int[CPU_GRP_SIZE];
    CreateHerd(CPU_GRP_SIZE, ph->px, ph->py, ph->distance, TAME);
  }
  
  if (keyIdx == 0)
    ::printf("[+] SolveKeyCPU Thread %02d: %d kangaroos\n", ph->threadId, CPU_GRP_SIZE);

  ph->hasStarted = true;
  Int dy, rx, ry, _s, _p;

  while (!endOfSearch) {
    for (int g = 0; g < CPU_GRP_SIZE; g++) {
#ifdef USE_SYMMETRY
      uint64_t jmp = ph->px[g].bits64[0] % (NB_JUMP / 2) + (NB_JUMP / 2) * ph->symClass[g];
#else
      uint64_t jmp = ph->px[g].bits64[0] % NB_JUMP;
#endif
      Int *p1x = &jumpPointx[jmp];
      Int *p2x = &ph->px[g];
      dx[g].ModSub(p2x, p1x);
    }
    grp->Set(dx);
    grp->ModInv();
    for (int g = 0; g < CPU_GRP_SIZE; g++) {
#ifdef USE_SYMMETRY
      uint64_t jmp = ph->px[g].bits64[0] % (NB_JUMP / 2) + (NB_JUMP / 2) * ph->symClass[g];
#else
      uint64_t jmp = ph->px[g].bits64[0] % NB_JUMP;
#endif
      Int *p1x = &jumpPointx[jmp];
      Int *p1y = &jumpPointy[jmp];
      Int *p2x = &ph->px[g];
      Int *p2y = &ph->py[g];
      dy.ModSub(p2y, p1y);
      _s.ModMulK1(&dy, &dx[g]);
      _p.ModSquareK1(&_s);
      rx.ModSub(&_p, p1x);
      rx.ModSub(p2x);
      ry.ModSub(p2x, &rx);
      ry.ModMulK1(&_s);
      ry.ModSub(p2y);
      ph->distance[g].ModAddK1order(&jumpDistance[jmp]);
#ifdef USE_SYMMETRY
      if (ry.ModPositiveK1()) {
        ph->distance[g].ModNegK1order();
        ph->symClass[g] = !ph->symClass[g];
      }
#endif
      ph->px[g].Set(&rx);
      ph->py[g].Set(&ry);
    }

    for (int g = 0; g < CPU_GRP_SIZE && !endOfSearch; g++) {
            if (IsDP(&ph->px[g])) {
                LOCK(ghMutex);
                if (!endOfSearch) {
                    if (!AddToTable(&ph->px[g], &ph->distance[g], g % 2)) {
                        CreateHerd(1, &ph->px[g], &ph->py[g], &ph->distance[g], g % 2, false);
                        collisionInSameHerd++;
                    }
                }
                UNLOCK(ghMutex);
            }
            if (!endOfSearch) counters[thId]++;
        }
    }

    if (saveRequest && !endOfSearch) {
        ph->isWaiting = true;
        LOCK(saveMutex);
        ph->isWaiting = false;
        UNLOCK(saveMutex);
    }

    delete grp;
    delete[] dx;
    safe_delete_array(ph->px);
    safe_delete_array(ph->py);
    safe_delete_array(ph->distance);
#ifdef USE_SYMMETRY
    safe_delete_array(ph->symClass);
#endif
    ph->isRunning = false;
}

void Kangaroo::SolveKeyGPU(TH_PARAM *ph) {
    double lastSent = 0;
    int thId = ph->threadId;
#ifdef WITHGPU
    std::vector<ITEM> dps;
    std::vector<ITEM> gpuFound;
    std::shared_ptr<GPUEngine> gpu = std::make_shared<GPUEngine>(ph->gridSizeX, ph->gridSizeY, ph->gpuId, 65536 * 2);
    if (keyIdx == 0)
        ::printf("[+] GPU: %s (%.1f MB used)\n", gpu->deviceName.c_str(), gpu->GetMemory() / 1048576.0);
    
    double t0 = Timer::get_tick();

    if (ph->px == nullptr) {
        if (keyIdx == 0)
            ::printf("[+] SolveKeyGPU Thread GPU#%d: creating kangaroos...\n", ph->gpuId);

        uint64_t nbThread = gpu->GetNbThread();
        ph->px = new Int[ph->nbKangaroo];
        ph->py = new Int[ph->nbKangaroo];
        ph->distance = new Int[ph->nbKangaroo];
        
        for (uint64_t i = 0; i < nbThread; i++) {
            CreateHerd(GPU_GRP_SIZE, &(ph->px[i * GPU_GRP_SIZE]), &(ph->py[i * GPU_GRP_SIZE]), &(ph->distance[i * GPU_GRP_SIZE]), TAME);
        }
    }

#ifdef USE_SYMMETRY
    gpu->SetWildOffset(&rangeWidthDiv4);
#else
    gpu->SetWildOffset(&rangeWidthDiv2);
#endif

    Int dmaskInt;
    HashTable::toInt(&dMask, &dmaskInt);
    gpu->SetParams(&dmaskInt, jumpDistance, jumpPointx, jumpPointy);
    gpu->SetKangaroos(ph->px, ph->py, ph->distance);

    if (workFile.empty() || !saveKangaroo) {
        safe_delete_array(ph->px);
        safe_delete_array(ph->py);
        safe_delete_array(ph->distance);
    }

    gpu->callKernel();
    double t1 = Timer::get_tick();
    
    if (keyIdx == 0)
        ::printf("[+] SolveKeyGPU Thread GPU#%d: 2^%.2f kangaroos [%.1fs]\n", ph->gpuId, log2(static_cast<double>(ph->nbKangaroo)), (t1 - t0));
    
    ph->hasStarted = true;

    std::vector<Int> cache_s(GPU_GRP_SIZE);
    std::vector<Int> cache_p(GPU_GRP_SIZE);

    while (!endOfSearch) {
        gpu->Launch(gpuFound);
        counters[thId] += ph->nbKangaroo * NB_RUN;

        if (!gpuFound.empty()) {
            LOCK(ghMutex);
            for (int g = 0; !endOfSearch && g < gpuFound.size(); g++) {
                uint32_t kType = gpuFound[g].kIdx % 2;

                if (!AddToTable(&gpuFound[g].x, &gpuFound[g].d, kType)) {
                    Int px, py, d;
                    CreateHerd(1, &px, &py, &d, kType, false);
                    gpu->SetKangaroo(gpuFound[g].kIdx, &px, &py, &d);
                    collisionInSameHerd++;
                }
            }
            UNLOCK(ghMutex);
        }
    }

    if (saveRequest && !endOfSearch) {
        if (saveKangaroo) gpu->GetKangaroos(ph->px, ph->py, ph->distance);
        ph->isWaiting = true;
        LOCK(saveMutex);
        ph->isWaiting = false;
        UNLOCK(saveMutex);
    }

    safe_delete_array(ph->px);
    safe_delete_array(ph->py);
    safe_delete_array(ph->distance);
    delete gpu;

#else
    ph->hasStarted = true;
#endif

    ph->isRunning = false;
}

void Kangaroo::CreateHerd(int nbKangaroo, Int *px, Int *py, Int *d, int firstType, bool lock) {
  vector<Int> pk(nbKangaroo);
  vector<Point> S(nbKangaroo);
  vector<Point> Sp(nbKangaroo);
  Point Z;
  Z.Clear();
  if (lock) LOCK(ghMutex);
  for (uint64_t j = 0; j < nbKangaroo; j++) {
    d[j].Rand(rangePower);
    if ((j + firstType) % 2 == WILD) {
      d[j].ModSubK1order(&rangeWidthDiv2);
    }
    pk[j] = d[j];
  }
  if (lock) UNLOCK(ghMutex);
  S = secp->ComputePublicKeys(pk);
  for (uint64_t j = 0; j < nbKangaroo; j++) {
    Sp[j] = ((j + firstType) % 2 == TAME) ? Z : keyToSearch;
  }
  S = secp->AddDirect(Sp, S);
  for (uint64_t j = 0; j < nbKangaroo; j++) {
    px[j].Set(&S[j].x);
    py[j].Set(&S[j].y);
    if (py[j].ModPositiveK1()) d[j].ModNegK1order();
  }
}

void Kangaroo::CreateJumpTable() {
    int jumpBit = std::max(10, std::min(256, rangePower / 2 + 1));
    int maxRetry = 100;
    bool ok = false;
    double distAvg;

    unsigned long seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine generator(seed);
    int seedValue = 363878;
    double desiredDeviation = seedValue;

    double maxAvg = pow(2.0, (double)jumpBit - 0.85);
    double minAvg = pow(2.0, (double)jumpBit - 1.05);
    double distances[NB_JUMP];
    std::normal_distribution<double> dist(pow(2, jumpBit) / 2.0, pow(2, jumpBit - 1) / 2.0);

    while (!ok && maxRetry > 0) {
        Int totalDist;
        totalDist.SetInt32(0);
        for (int i = 0; i < NB_JUMP; ++i) {
            double jumpValue = dist(generator);
            jumpValue = std::max(1.0, jumpValue);
            jumpDistance[i].SetInt32(static_cast<int>(jumpValue));
            totalDist.Add(&jumpDistance[i]);
            distances[i] = jumpDistance[i].ToDouble();
        }
        distAvg = totalDist.ToDouble() / (double)(NB_JUMP);
        double deviation = calculateDeviation(distances, NB_JUMP);
        ok = distAvg > minAvg && distAvg < maxAvg && deviation < desiredDeviation;
        maxRetry--;
    }

    for (int i = 0; i < NB_JUMP; ++i) {
        Point J = secp->ComputePublicKey(&jumpDistance[i]);
        jumpPointx[i].Set(&J.x);
        jumpPointy[i].Set(&J.y);
    }

    ::printf("[+] Jump Avg distance: 2^%.2f, Deviation: %.2f\n", log2(distAvg), calculateDeviation(distances, NB_JUMP));
}



double Kangaroo::calculateDeviation(double* distances, int size) {
    double sum = 0.0, mean, deviation = 0.0;

    for (int i = 0; i < size; ++i) {
        sum += distances[i];
    }
    mean = sum / size;

    for (int i = 0; i < size; ++i) {
        deviation += pow(distances[i] - mean, 2);
    }
    return sqrt(deviation / size);
}

void Kangaroo::ComputeExpected(double dp, double *op, double *ram, double *overHead) {
#ifdef USE_SYMMETRY
  double gainS = 1.0 / sqrt(2.0);
#else
  double gainS = 1.0;
#endif
  double k = static_cast<double>(totalRW);
  double N = pow(2.0, static_cast<double>(rangePower));
  double theta = pow(2.0, dp);
  double Z0 = (2.0 * (2.0 - sqrt(2.0)) * gainS) * sqrt(M_PI);
  double avgDP0 = Z0 * sqrt(N);
  *op = Z0 * pow(N * (k * theta + sqrt(N)), 1.0 / 3.0);
  *ram = (sizeof(HASH_ENTRY) * HASH_SIZE +
          sizeof(ENTRY *) * (HASH_SIZE * 4) +
          (sizeof(ENTRY) + sizeof(ENTRY *)) * (*op / theta)) / (1024.0 * 1024.0);
  if (overHead) *overHead = *op / avgDP0;
}

void Kangaroo::InitRange() {
  rangeWidth.Set(&rangeEnd);
  rangeWidth.Sub(&rangeStart);
  rangePower = rangeWidth.GetBitLength();
  ::printf("[+] Range width: 2^%d\n", rangePower);
  rangeWidthDiv2.Set(&rangeWidth);
  rangeWidthDiv2.ShiftR(1);
  rangeWidthDiv4.Set(&rangeWidthDiv2);
  rangeWidthDiv4.ShiftR(1);
  rangeWidthDiv8.Set(&rangeWidthDiv4);
  rangeWidthDiv8.ShiftR(1);
}

void Kangaroo::InitSearchKey() {
  Int SP;
  SP.Set(&rangeStart);
#ifdef USE_SYMMETRY
  SP.ModAddK1order(&rangeWidthDiv2);
#endif
  if (!SP.IsZero()) {
    Point RS = secp->ComputePublicKey(&SP);
    RS.y.ModNeg();
    keyToSearch = secp->AddDirect(keysToSearch[keyIdx], RS);
  } else {
    keyToSearch = keysToSearch[keyIdx];
  }
  keyToSearchNeg = keyToSearch;
  keyToSearchNeg.y.ModNeg();
}

void Kangaroo::Run(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize) {
    double t0 = Timer::get_tick();
    nbCPUThread = nbThread;
    nbGPUThread = (useGpu ? (int)gpuId.size() : 0);
    totalRW = 0;
#ifndef WITHGPU
    if (nbGPUThread > 0) {
        ::printf("GPU code not compiled, use -DWITHGPU when compiling.\n");
        nbGPUThread = 0;
    }
#endif
    uint64_t totalThread = (uint64_t)nbCPUThread + (uint64_t)nbGPUThread;
    if (totalThread == 0) {
        ::printf("No CPU or GPU thread, exiting.\n");
        ::exit(0);
    }
    TH_PARAM *params = (TH_PARAM *)malloc(totalThread * sizeof(TH_PARAM));
    THREAD_HANDLE *thHandles = (THREAD_HANDLE *)malloc(totalThread * sizeof(THREAD_HANDLE));
    memset(params, 0, totalThread * sizeof(TH_PARAM));
    memset(counters, 0, sizeof(counters));
    ::printf("[+] Number of CPU thread: %d\n", nbCPUThread);
#ifdef WITHGPU
    for (int i = 0; i < nbGPUThread; i++) {
        int x = gridSize[2ULL * i];
        int y = gridSize[2ULL * i + 1ULL];
        if (!GPUEngine::GetGridSize(gpuId[i], &x, &y)) {
            free(params);
            free(thHandles);
            return;
        } else {
            params[nbCPUThread + i].gridSizeX = x;
            params[nbCPUThread + i].gridSizeY = y;
        }
        params[nbCPUThread + i].nbKangaroo = (uint64_t)GPU_GRP_SIZE * x * y;
        totalRW += params[nbCPUThread + i].nbKangaroo;
    }
#endif
    totalRW += nbCPUThread * (uint64_t)CPU_GRP_SIZE;
    InitRange();
    CreateJumpTable();
    ::printf("[+] Number of kangaroos: 2^%.2f\n", log2((double)totalRW));

    int suggestedDP = initDPSize;
    double dpOverHead;
    ComputeExpected((double)suggestedDP, &expectedNbOp, &expectedMem, &dpOverHead);
    while (dpOverHead > 1.05 && suggestedDP > 0) {
        suggestedDP--;
        ComputeExpected((double)suggestedDP, &expectedNbOp, &expectedMem, &dpOverHead);
    }
    if (initDPSize < 0) initDPSize = suggestedDP;
    ComputeExpected((double)initDPSize, &expectedNbOp, &expectedMem);

    ::printf("[+] Expected operations: 2^%.2f\n", log2(expectedNbOp));

    keyIdx = 0;
    InitSearchKey();
    SetDP(initDPSize);
    FectchKangaroos(params);
#ifdef STATS
    CPU_GRP_SIZE = 1024;
    for (; CPU_GRP_SIZE <= 1024; CPU_GRP_SIZE *= 4) {
        uint64_t totalCount = 0;
        uint64_t totalDead = 0;
#endif
        for (keyIdx = 0; keyIdx < keysToSearch.size(); keyIdx++) {
            InitSearchKey();
            endOfSearch = false;
            collisionInSameHerd = 0;
            memset(counters, 0, sizeof(counters));
            for (int i = 0; i < nbCPUThread; i++) {
                params[i].threadId = i;
                params[i].isRunning = true;
                thHandles[i] = LaunchThread(std::function<void(TH_PARAM*)>([](TH_PARAM* param) {
                    param->obj->SolveKeyCPU(param);
                }), params + i);
            }
#ifdef WITHGPU
            for (int i = 0; i < nbGPUThread; i++) {
                int id = nbCPUThread + i;
                params[id].threadId = 0x80L + i;
                params[id].isRunning = true;
                params[id].gpuId = gpuId[i];

                thHandles[id] = LaunchThread(std::function<void(TH_PARAM*)>([this](TH_PARAM* param) {
                    SolveKeyGPU(param);
                }), params + id);
            }
#endif
            Process(params, "MK/s");
            JoinThreads(thHandles, nbCPUThread + nbGPUThread);
            FreeHandles(thHandles, nbCPUThread + nbGPUThread);
            hashTable.Reset();
#ifdef STATS
            uint64_t count = getCPUCount() + getGPUCount();
            totalCount += count;
            totalDead += collisionInSameHerd;
            double SN = pow(2.0, rangePower / 2.0);
            double avg = (double)totalCount / (double)(keyIdx + 1);
            ::printf("\n[+] [%3d] 2^%.3f Dead:%d Avg:2^%.3f DeadAvg:%.1f (%.3f %.3f sqrt(N))\n",
                     keyIdx, log2((double)count), (int)collisionInSameHerd, log2(avg),
                     (double)totalDead / (double)(keyIdx + 1), avg / SN, expectedNbOp / SN);
        }
        string fName = "DP" + ::to_string(dpSize) + ".txt";
        FILE *f = fopen(fName.c_str(), "a");
        fprintf(f, "[+] %d %f\n", CPU_GRP_SIZE * nbCPUThread, (double)totalCount);
        fclose(f);
#endif
    }
    double t1 = Timer::get_tick();
    ::printf("\n[+] Done: Total time %s \n", GetTimeStr(t1 - t0 + offsetTime).c_str());
}
