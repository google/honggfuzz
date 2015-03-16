perl -pi -e "s/\sif\s*\(([a-z0-9A-Z_\.\->]+)\s*==\s*([a-z0-9A-Z_\.\->\[\]]+)\)(\s*{|\s*)$/ if (_CMP_EQ((unsigned long long)(\1), (unsigned long long)(\2)))\3/" *.c *.h

perl -pi -e "s/\sif\s*\(([a-z0-9A-Z_\.\->]+)\s*!=\s*([a-z0-9A-Z_\.\->\[\]]+)\)(\s*{|\s*)$/ if (_CMP_NEQ((unsigned long long)(\1), (unsigned long long)(\2)))\3/" *.c *.h
