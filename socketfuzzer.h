#include "honggfuzz.h"

bool fuzz_waitForExternalInput(run_t* run);

bool fuzz_prepareSocketFuzzer(run_t* run);
int fuzz_waitforSocketFuzzer(run_t* run);

bool fuzz_notifySocketFuzzerNewCov(honggfuzz_t* hfuzz);
bool fuzz_notifySocketFuzzerCrash(run_t* run);

bool setupSocketFuzzer(honggfuzz_t* hfuzz);
void cleanupSocketFuzzer();
