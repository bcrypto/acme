#!/usr/bin/env sh

scripts_dir="$( dirname "${BASH_SOURCE[0]}" )"
source $scripts_dir/../.env
# This path should be to builded bee2evp directory
bee2evp=$(cd $scripts_dir/../$BEE2EVP_PATH && pwd)
build_root=$bee2evp/build
local=${BEE2EVP_INSTALL_DIR:-$build_root/local}
lib_path=$local/lib

run_bee2py(){
  export PATH=$local/bin:$PATH
  export OPENSSL_CONF=$local/openssl.cnf
  export LD_LIBRARY_PATH="$lib_path:${LD_LIBRARY_PATH}"
  export DYLD_LIBRARY_PATH="$lib_path:$DYLD_LIBRARY_PATH"
  python3 $@
}
run_bee2py $@