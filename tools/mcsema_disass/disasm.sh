#!/bin/bash



# saner programming env: these switches turn some bugs into errors
set -o errexit -o pipefail -o noclobber -o nounset

! getopt --test > /dev/null 
if [[ ${PIPESTATUS[0]} -ne 4 ]]; then
    echo "I’m sorry, `getopt --test` failed in this environment."
    exit 1
fi

OPTIONS=dei:v
LONGOPTS=debug,entrypoint,input:

# -use ! and PIPESTATUS to get exit code with errexit set
# -temporarily store output to be able to check for errors
# -activate quoting/enhanced mode (e.g. by writing out “--options”)
# -pass arguments only via   -- "$@"   to separate them correctly
! PARSED=$(getopt --options=$OPTIONS --longoptions=$LONGOPTS --name "$0" -- "$@")
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    # e.g. return value is 1
    #  then getopt has complained about wrong arguments to stdout
    exit 2
fi
# read getopt’s output this way to handle the quoting right:
eval set -- "$PARSED"

DEBUG=False
ENTRY=entry0

d=n e=entry0 BINARY=-
# now enjoy the options in order and nicely split until we see --
while true; do
    case "$1" in
        -d|--debug)
            DEBUG=True
            shift
            ;;
        -e|--entrypoint)
            ENTRY="$2"
            shift 2
            ;;
        -i|--input)
            BINARY="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -h|--help)
	    echo "This is a test script for the McSema radare2 backend for Mach-O binaries"
	    echo "Usage:"

	    echo "$0 [--debug] [--entrypoint <entry>] <binary>"
            exit 3
            ;;
    esac
done

echo "debug: $DEBUG, in: $BINARY"

DEBUG=False
python __main__.py --disassembler r2 --Debug $DEBUG --arch aarch64 --os linux --output $BINARY.r2.cfg --binary $BINARY --entrypoint $ENTRY
