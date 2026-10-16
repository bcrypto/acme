#!/bin/bash
# *****************************************************************************
# \file source.sh
# \project Acme 
# \brief Reusable script code
# \created 2026.10.14
# \version 2026.10.16
# \copyright The Acme authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

set -eo pipefail

green () { printf "\e[32m" ; $@ ; printf "\e[0m"; }
red () { printf "\e[31m" ; $@ ; printf "\e[0m"; }


default_opt() {
  enable_setup=false
  enable_build=false
  enable_test=false
  openssl_tag="openssl-3.5.6"
}


system_opt(){
  ossl_config=""
  make=make

  os_name=$(uname -s)
  arch=$(uname -m)

  echo "System detection: OS=$os_name, Arch=$arch"

  case "$os_name" in
    Linux)
      # Linux distribution detection
      ossl_config="linux-$arch"
      ;;
    Darwin)
      # macOS detection
      ossl_config="darwin64-$arch-cc"
      ;;
    FreeBSD)
      # OpenSSL detects the target itself, its Makefile needs GNU make
      make=gmake
      ;;
    CYGWIN*|MINGW*|MSYS*)
      # Windows via Cygwin/MSYS2/MinGW
      ossl_config="Cygwin-$arch"
      ;;
    *)
      # Fallback for unknown systems
      echo "Unknown system. Default settings are used."
      ;;
  esac
}

parse_opt() {
  case $1 in
    -s)
      enable_setup=true
      ;;
    -t)
      enable_test=true
      ;;
    -b)
      enable_build=true
      ;;
    -h|--help)
      ;;
    -*)
      red echo "invalid option -- $1" >&2
      usage
      ;;
    *)
      if [[ ! -z "$1" ]]; then
        openssl_tag="$1"
      else
        usage
      fi
      ;;
  esac
}


set_dir(){
  scripts_dir="$( dirname "${BASH_SOURCE[0]}" )"
  acme=$(cd $scripts_dir/../ && pwd)
  cd $acme
  mkdir -p build
  build_root=$acme/build
  bee2evp=$(cd $scripts_dir/../$BEE2EVP_PATH && pwd)
  patch=$acme/patch
  cryptography=$build_root/cryptography
  build_openssl=$build_root/build_openssl
  local=$build_root/local
  openssl=$build_root/openssl
  bee2evp_local=$bee2evp/build/local/openssl
  openssl_git_url=https://github.com/openssl/openssl.git
  cryptography_git_url=https://github.com/pyca/cryptography.git
}

set_venv(){
  pip install -U setuptools
  pip install -U wheel pip
}

clean(){
  green echo "[-] clean build files..."
  rm -rf $build_root
}

# Check if openssl tag exist.
check_openssl_tag(){
  green echo "[-] check openssl tag"
  git ls-remote $openssl_git_url refs/tags/$openssl_tag
}

update_repos(){
  green echo "[-] update repos"
  git_opt="-c advice.detachedHead=false --depth 1"
  git clone $git_opt -b $openssl_tag $openssl_git_url $openssl
  git clone $git_opt -b $cryptography_tag $cryptography_git_url $cryptography
}

patch_cryptography(){
  green echo "[-] patch cryptography"
  c_patch=$patch/cryptography
  src_cryptography=$cryptography/src/cryptography
  cd $cryptography
  cp $c_patch/provided.py $src_cryptography/hazmat/primitives/asymmetric/ 
  git apply $c_patch/cryptography.patch
}

build_openssl(){
  green echo "[-] build openssl"
  mkdir -p $build_openssl && cd $build_openssl
  ossl_opt="--prefix=$local --openssldir=$local --libdir=lib"
  $openssl/Configure $ossl_config $ossl_opt no-shared no-ssl2 no-ssl3 -fPIC 
  $make -j$(nproc) all
  $make install > build.log 2>&1 || (cat build.log && exit 1)
}

install_cryptography(){
  green echo "[-] install cryptography"
  cd $cryptography
  pip_opt="--no-cache-dir --no-binary"
  OPENSSL_DIR="$local" pip wheel $pip_opt cryptography cryptography
  pip install .  
}


setup(){
  green echo "Setup..."
  clean
  mkdir -p $build_root && cd $build_root
  set_venv
  check_openssl_tag
  update_repos
  patch_cryptography
  build_openssl
  green echo "Setup ended"
}

build(){
  green echo "Building..."
  install_cryptography
  green echo "Build ended"
}