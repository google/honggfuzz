#!/bin/bash

DIR="/var/www/tmin"
WWWUSER="www-data"

if [ ! -f "$DIR/testcase.in" ]; then
  echo "Test case $DIR/testcase.in not found."
  exit 1
fi

if [ ! -x "$DIR/tmin" ]; then
  echo "Executable file $DIR/tmin not found."
  exit 1
fi

if [ ! -x "$DIR/deny.cgi" -o ! -x "$DIR/confirm.cgi" -o ! -x "$DIR/data.cgi" -o ! -f "$DIR/index.html" ]; then
  echo "Required CGI files in $DIR/ not found."
  exit 1
fi

if [ ! "$USER" = "$WWWUSER" ]; then
  echo "This script must be run as user '$WWWUSER' (use su/sudo)."
  exit 1
fi

cd "$DIR" || exit $?

rm -f tmin.data || exit $?

./tmin -s -w tmin.data /bin/true
exit $?