#
# tmin - Makefile
# ---------------
#
# Author: Michal Zalewski <lcamtuf@google.com>
# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

PROGNAME = tmin
CFLAGS	 = -Wall -O3 -funroll-loops -fno-strict-aliasing -Wno-pointer-sign

all: $(PROGNAME)

clean:
	rm -f $(PROGNAME) *.exe *.o *~ a.out core core.[1-9][0-9]* *.stackdump
