#!/usr/bin/env bash

pkg=$1

PROJECT_ROOT=$PWD

mkdir -p "./fuzz/${pkg}"

cd "./fuzz/${pkg}"

apt source $pkg

DEB_BUILD_OPTIONS="nocheck nostrip parallel=$(nproc)" \
    ${PROJECT_ROOT}/main -mode=modify -module ${PROJECT_ROOT}/ccswap.so -- \
    sbuild -v -d trixie --arch-any --no-arch-all --no-source *.dsc \
    --chroot-setup-commands="apt update; DEBIAN_FRONTEND=noninteractive apt install -y afl++;" \
    --finished-build-commands="exe=\$(find /build -type f -executable -name ${pkg} 2>/dev/null | head -n 1); ehco \$exe;\
        mkdir -p /tmp/fuzz/afl-in; echo A > /tmp/fuzz/afl-in/seed.txt;\
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 timeout 1m\
        afl-fuzz -i /tmp/fuzz/afl-in -o /tmp/fuzz/afl-out -- \$exe || true;" \
    2>&1 | tee build.log

