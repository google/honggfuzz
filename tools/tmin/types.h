/*

   tmin - type definitions
   -----------------------
   
   A couple of semi-portable integer types with reasonably short names.

   Author: Michal Zalewski <lcamtuf@google.com>
   Copyright 2008 Google Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#ifndef _HAVE_TYPES_H
#define _HAVE_TYPES_H

typedef unsigned char		_u8;
typedef unsigned short		_u16;
typedef unsigned int		_u32;

#ifdef WIN32
typedef unsigned __int64	_u64;
#else
typedef unsigned long long	_u64;
#endif /* ^WIN32 */

typedef signed char		_s8;
typedef signed short		_s16;
typedef signed int		_s32;

#ifdef WIN32
typedef signed __int64		_s64;
#else
typedef signed long long	_s64;
#endif /* ^WIN32 */

#endif /* ! _HAVE_TYPES_H */
