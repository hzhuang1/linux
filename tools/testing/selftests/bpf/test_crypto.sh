#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Kselftest framework requirement - SKIP code is 4.
ksft_skip=4
ret=$ksft_skip

msg="skip all tests:"
if [ $UID != 0 ]; then
	echo $msg please run this as root >&2
	exit $ksft_skip
fi

GREEN='\033[0;92m'
RED='\033[0;31m'
NC='\033[0m' # No Color

./test_crypto_user
ret=$?

exit $ret
