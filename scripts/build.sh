#!/bin/bash
# *****************************************************************************
# \file build.sh
# \project Acme 
# \brief Common build script
# \created 2026.10.14
# \version 2026.10.14
# \copyright The Acme authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

scripts_dir="$( dirname "${BASH_SOURCE[0]}" )"
source $scripts_dir/../.env
source $scripts_dir/source.sh

cryptography_tag="50.0.2"

default_opt

system_opt

while [[ $# -gt 0 ]]; do
  parse_opt $1
  shift
done

set_dir

if $enable_setup; then
  setup
fi

if $enable_build; then
  build
fi

if $enable_test; then
  test_cryptography
fi