#include "Kangaroo.h"
#include "Timer.h"
#include <string.h>
#define _USE_MATH_DEFINES
#include <math.h>
#include <algorithm>
#ifndef WIN64
#include <pthread.h>
#endif
using namespace std;

// ----------------------------------------------------------------------------
#ifdef WIN64
THREAD_HANDLE Kangaroo::LaunchThread(LPTHREAD_START_ROUTINE func, TH_PARAM *p) {
    p->obj = this;
    return CreateThread(NULL, 0, func, (void*)(p), 0, NULL);
}

THREAD_HANDLE Kangaroo::LaunchThread(std::function<void(TH_PARAM*)> func, TH_PARAM *p) {
    p->obj = this;
    return CreateThread(NULL, 0, [](LPVOID lpParam) -> DWORD {
        auto* params = static_cast<std::pair<std::function<void(TH_PARAM*)>, TH_PARAM*>*>(lpParam);
        params->first(params->second);
        delete params;
        return 0;
    }, new std::pair<std::function<void(TH_PARAM*)>, TH_PARAM*>(func, p), 0, NULL);
}

void Kangaroo::JoinThreads(THREAD_HANDLE *handles, int nbThread) {
    WaitForMultipleObjects(nbThread, handles, TRUE, INFINITE);
}

void Kangaroo::FreeHandles(THREAD_HANDLE *handles, int nbThread) {
    for (int i = 0; i < nbThread; i++)
        CloseHandle(handles[i]);
}
#else
THREAD_HANDLE Kangaroo::LaunchThread(void *(*func)(void*), TH_PARAM *p) {
    THREAD_HANDLE h;
    p->obj = this;
    pthread_create(&h, NULL, func, (void*)(p));
    return h;
}

THREAD_HANDLE Kangaroo::LaunchThread(std::function<void(TH_PARAM*)> func, TH_PARAM *p) {
    p->obj = this;
    auto params = new std::pair<std::function<void(TH_PARAM*)>, TH_PARAM*>(func, p);
    THREAD_HANDLE handle;
    pthread_create(&handle, nullptr, [](void* lpParam) -> void* {
        auto* params = static_cast<std::pair<std::function<void(TH_PARAM*)>, TH_PARAM*>*>(lpParam);
        params->first(params->second);
        delete params;
        return nullptr;
    }, params);
    return handle;
}

void Kangaroo::JoinThreads(THREAD_HANDLE *handles, int nbThread) {
    for (int i = 0; i < nbThread; i++)
        pthread_join(handles[i], NULL);
}

void Kangaroo::FreeHandles(THREAD_HANDLE *handles, int nbThread) {}
#endif

// ----------------------------------------------------------------------------
bool Kangaroo::isAlive(TH_PARAM *p) {
    bool isAlive = false;
    int total = nbCPUThread + nbGPUThread;
    for (int i = 0; i < total; i++)
        isAlive = isAlive || p[i].isRunning;
    return isAlive;
}

// ----------------------------------------------------------------------------
bool Kangaroo::hasStarted(TH_PARAM *p) {
    bool hasStarted = true;
    int total = nbCPUThread + nbGPUThread;
    for (int i = 0; i < total; i++)
        hasStarted = hasStarted && p[i].hasStarted;
    return hasStarted;
}

// ----------------------------------------------------------------------------
bool Kangaroo::isWaiting(TH_PARAM *p) {
    bool isWaiting = true;
    int total = nbCPUThread + nbGPUThread;
    for (int i = 0; i < total; i++)
        isWaiting = isWaiting && p[i].isWaiting;
    return isWaiting;
}

// ----------------------------------------------------------------------------
uint64_t Kangaroo::getGPUCount() {
    uint64_t count = 0;
    for (int i = 0; i < nbGPUThread; i++)
        count += counters[0x80L + i];
    return count;
}

// ----------------------------------------------------------------------------
uint64_t Kangaroo::getCPUCount() {
    uint64_t count = 0;
    for (int i = 0; i < nbCPUThread; i++)
        count += counters[i];
    return count;
}

// ----------------------------------------------------------------------------
string Kangaroo::GetTimeStr(double dTime) {
    if (dTime < 1) return "00s";
    char tmp[256];
    double nbDay = dTime / 86400.0;
    if (nbDay >= 1) {
        double nbYear = nbDay / 365.0;
        if (nbYear > 1) {
            if (nbYear < 5)
                sprintf(tmp, "%.1fy", nbYear);
            else
                sprintf(tmp, "%gy", nbYear);
        } else {
            sprintf(tmp, "%.1fd", nbDay);
        }
    } else {
        int iTime = (int)dTime;
        int nbHour = (int)((iTime % 86400) / 3600);
        int nbMin = (int)(((iTime % 86400) % 3600) / 60);
        int nbSec = (int)(iTime % 60);
        if (nbHour == 0) {
            if (nbMin == 0) {
                sprintf(tmp, "%02ds", nbSec);
            } else {
                sprintf(tmp, "%02d:%02d", nbMin, nbSec);
            }
        } else {
            sprintf(tmp, "%02d:%02d:%02d", nbHour, nbMin, nbSec);
        }
    }
    return string(tmp);
}

void Kangaroo::Process(TH_PARAM *params, std::string unit) {
    double t0, t1;
    uint64_t count, lastCount = 0, gpuCount = 0, lastGPUCount = 0;
    double avgKeyRate = 0.0, avgGpuKeyRate = 0.0, lastSave = 0;
#ifndef WIN64
    setvbuf(stdout, NULL, _IONBF, 0);
#endif
    // Key rate smoothing filter
#define FILTER_SIZE 8
    double lastkeyRate[FILTER_SIZE] = {0};
    double lastGpukeyRate[FILTER_SIZE] = {0};
    uint32_t filterPos = 0;
    // Wait until all threads have started
    while (!hasStarted(params)) Timer::SleepMillis(5);
    t0 = Timer::get_tick();
    startTime = t0;
    lastGPUCount = getGPUCount();
    lastCount = getCPUCount() + gpuCount;
    while (isAlive(params)) {
        int delay = 2000;
        while (isAlive(params) && delay > 0) {
            Timer::SleepMillis(50);
            delay -= 50;
        }
        gpuCount = getGPUCount();
        count = getCPUCount() + gpuCount;
        t1 = Timer::get_tick();
        double keyRate = (double)(count - lastCount) / (t1 - t0);
        double gpuKeyRate = (double)(gpuCount - lastGPUCount) / (t1 - t0);
        lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
        lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
        filterPos++;
        
        // KeyRate smoothing
        avgKeyRate = 0.0;
        avgGpuKeyRate = 0.0;
        uint32_t nbSample;
        for (nbSample = 0; (nbSample < FILTER_SIZE) && (nbSample < filterPos); nbSample++) {
            avgKeyRate += lastkeyRate[nbSample];
            avgGpuKeyRate += lastGpukeyRate[nbSample];
        }
        avgKeyRate /= (double)(nbSample);
        avgGpuKeyRate /= (double)(nbSample);

        // Check for zero avgKeyRate
        if (avgKeyRate == 0) {
            printf("Warning: avgKeyRate is zero, cannot calculate expectedTime\n");
            avgKeyRate = 1.0;  // Prevent division by zero
        }

        double expectedTime = expectedNbOp / avgKeyRate;
        // Display stats
        if (isAlive(params) && !endOfSearch) {
            printf("[+] [%.2f %s][GPU %.2f %s][Count 2^%.2f][Dead %.0f][%s (Avg %s)][%s] \r",
                avgKeyRate / 1000000.0, unit.c_str(),
                avgGpuKeyRate / 1000000.0, unit.c_str(),
                log2((double)count + offsetCount),
                (double)collisionInSameHerd,
                GetTimeStr(t1 - startTime + offsetTime).c_str(), GetTimeStr(expectedTime).c_str(),
                hashTable.GetSizeInfo().c_str()
            );
        }
    }
    // Save request
    if (workFile.length() > 0 && !endOfSearch) {
        if ((t1 - lastSave) > saveWorkPeriod) {
            SaveWork(count + offsetCount, t1 - startTime + offsetTime, params, nbCPUThread + nbGPUThread);
            lastSave = t1;
        }
    }

    // Abort
    lastCount = count;
    lastGPUCount = gpuCount;
    t0 = t1;
    count = getCPUCount() + getGPUCount();
    t1 = Timer::get_tick();
    if (!endOfSearch) {
        printf("\r[%.2f %s][GPU %.2f %s][Cnt 2^%.2f][%s]  ",
            avgKeyRate / 1000000.0, unit.c_str(),
            avgGpuKeyRate / 1000000.0, unit.c_str(),
            log2((double)count),
            GetTimeStr(t1 - startTime).c_str()
        );
    }
}
