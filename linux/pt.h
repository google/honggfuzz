/*
 *
 * honggfuzz - Intel PT decoder
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#ifndef _HF_LINUX_PT_H_
#define _HF_LINUX_PT_H_

#include "honggfuzz.h"

extern void arch_ptAnalyze(run_t* run);
extern void perf_ptInit(void);

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#define RTIT_CTL_TRACEEN BIT(0)
#define RTIT_CTL_CYCLEACC BIT(1)
#define RTIT_CTL_OS BIT(2)
#define RTIT_CTL_USR BIT(3)
#define RTIT_CTL_PWR_EVT_EN BIT(4)
#define RTIT_CTL_FUP_ON_PTW BIT(5)
#define RTIT_CTL_CR3EN BIT(7)
#define RTIT_CTL_TOPA BIT(8)
#define RTIT_CTL_MTC_EN BIT(9)
#define RTIT_CTL_TSC_EN BIT(10)
#define RTIT_CTL_DISRETC BIT(11)
#define RTIT_CTL_PTW_EN BIT(12)
#define RTIT_CTL_BRANCH_EN BIT(13)
#define RTIT_CTL_MTC_RANGE_OFFSET 14
#define RTIT_CTL_MTC_RANGE (0x0full << RTIT_CTL_MTC_RANGE_OFFSET)
#define RTIT_CTL_CYC_THRESH_OFFSET 19
#define RTIT_CTL_CYC_THRESH (0x0full << RTIT_CTL_CYC_THRESH_OFFSET)
#define RTIT_CTL_PSB_FREQ_OFFSET 24
#define RTIT_CTL_PSB_FREQ (0x0full << RTIT_CTL_PSB_FREQ_OFFSET)
#define RTIT_CTL_ADDR0_OFFSET 32
#define RTIT_CTL_ADDR0 (0x0full << RTIT_CTL_ADDR0_OFFSET)
#define RTIT_CTL_ADDR1_OFFSET 36
#define RTIT_CTL_ADDR1 (0x0full << RTIT_CTL_ADDR1_OFFSET)
#define RTIT_CTL_ADDR2_OFFSET 40
#define RTIT_CTL_ADDR2 (0x0full << RTIT_CTL_ADDR2_OFFSET)
#define RTIT_CTL_ADDR3_OFFSET 44
#define RTIT_CTL_ADDR3 (0x0full << RTIT_CTL_ADDR3_OFFSET)
#define RTIT_STATUS_FILTEREN BIT(0)
#define RTIT_STATUS_CONTEXTEN BIT(1)
#define RTIT_STATUS_TRIGGEREN BIT(2)
#define RTIT_STATUS_BUFFOVF BIT(3)
#define RTIT_STATUS_ERROR BIT(4)
#define RTIT_STATUS_STOPPED BIT(5)

#endif /* _HF_LINUX_INTEL_PT_LIB */
