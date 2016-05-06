#!/usr/bin/env sh
#
#   honggfuzz stackhash blacklist file create script
#   -----------------------------------------
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

set -e # fail on unhandled error
set -u # fail on undefined variable
#set -x # debug

readonly tmpFile=$(pwd)/.hf.bl.txt
declare -a sysTools=("perl" "cut" "sort" "paste" "wc" "tr" "cat")

usage() {
cat <<_EOF

  Usage: $(basename $0) [options]
    OPTIONS:
      -i|--input   : input crash(es) directory / file
      -B|--bl-file : output file to save found hashes (merge if exists)
      -e|--ext     : file extension of fuzzer files (e.g. fuzz)
      -a|--arch    : arch fuzzer have run against ('MAC' or 'LINUX')

    INFO:
      * Blacklist file sort mode only requires [-B/--bl-file] argument
      * Hashes gather mode requires all argument to be set
_EOF
  exit 1
}

command_exists () {
    type "$1" &> /dev/null ;
}

# Check that system tools exist
for i in "${sysTools[@]}"
do
  if ! command_exists $i; then
    echo "[-] '$i' command not found"
    exit 1
  fi
done

INPUT_DIR=""
BL_FILE=""
FILE_EXT=""
ARCH=""

nArgs=$#
while [[ $# > 1 ]]
do
  arg="$1"
  case $arg in
    -i|--input)
      INPUT_DIR="$2"
      shift
      ;;
    -B|--bl-file)
      BL_FILE="$2"
      shift
      ;;
    -e|--ext)
      FILE_EXT="$2"
      shift
      ;;
    -a|--arch)
      ARCH="$2"
      shift
      ;;
    *)
      echo "[-] Invalid argument '$1'"
      usage
      ;;
  esac
  shift
done

gatherMode=false

# Sort only mode
if [[ "$BL_FILE" == "" ]]; then
  echo "[-] Missing blacklist file"
  usage
fi

# Hashes gather mode
if [ $nArgs -gt 2 ]; then
  if [[ "$INPUT_DIR" == "" || ! -e "$INPUT_DIR" ]]; then
    echo "[-] Missing or invalid input directory"
    usage
  fi

  if [[ "$FILE_EXT" == "" ]]; then
    echo "[-] Missing file extension"
    usage
  fi

  if [[ "$ARCH" != "MAC" && "$ARCH" != "LINUX" ]]; then
    echo "[-] Invalid architecture, expecting 'MAC' or 'LINUX'"
    usage
  fi

  if [[ "$ARCH" == "LINUX" ]]; then
    STACKHASH_FIELD=5
  elif [[ "$ARCH" == "MAC" ]]; then
    STACKHASH_FIELD=6
  else
    echo "[-] Unsupported architecture"
    exit 1
  fi
  gatherMode=true
fi

# save old data
if [ -f $BL_FILE ]; then
  cat $BL_FILE > $tmpFile
  oldCount=$(cat $BL_FILE | wc -l | tr -d " ")
else
  oldCount=0
fi

if $gatherMode; then
  echo "[*] Processing files from '$INPUT_DIR' ..."
  find $INPUT_DIR -type f -iname "*.$FILE_EXT" | while read -r FILE
  do
    fileName=$(basename $FILE)
    if ! echo $fileName | grep -qF ".STACK."; then
      echo "[!] Skipping '$FILE'"
      continue
    fi
    stackHash=$(echo $fileName | cut -d '.' -f$STACKHASH_FIELD)

    # We don't want to lose crashes where unwinder failed
    if [[ "$stackHash" != "0" && ! "$stackHash" =~ ^badbad.* ]]; then
      echo $stackHash >> $tmpFile
    fi
  done
fi

# sort hex values
echo "[*] Sorting blacklist file entries"
perl -lpe '$_=hex' $tmpFile | \
paste -d" " - $tmpFile  | sort -nu | cut -d" " -f 2- \
> $BL_FILE

entries=$(cat $BL_FILE | wc -l | tr -d " ")
echo "[*] $BL_FILE contains $entries blacklisted stack hashes"

rm $tmpFile
