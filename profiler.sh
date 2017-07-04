#!/bin/bash

usage() {
    echo "Usage: $0 [options] <pid>"
    echo "Options:"
    echo "  --start           start profiling and return immediately"
    echo "  --stop            stop profiling"
    echo "  --status          print profiling status"
    echo "  -d duration       run profiling for <duration> seconds"
    echo "  -f filename       dump output to <filename>"
    echo "  -i interval       sampling interval in nanoseconds"
    echo "  -b bufsize        frame buffer size"
    echo "  -o fmt[,fmt...]   output format: summary|traces|methods|flamegraph"
    echo ""
    echo "Example: $0 -d 30 -f profile.fg -o flamegraph 3456"
    echo "         $0 --start -i 999000 3456"
    echo "         $0 --stop -o summary,methods 3456"
    exit 1
}

OPTIND=1
SCRIPT_DIR=$(dirname $0)
JATTACH=$SCRIPT_DIR/build/jattach
# realpath is not present on all distros, notably on the Travis CI image
PROFILER=$(readlink -f $SCRIPT_DIR/build/libasyncProfiler.so)
ACTION=""
DURATION="60"
FILE=""
INTERVAL=""
FRAMEBUF=""
OUTPUT="summary,traces=200,methods=200"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|"-?")
            usage
            ;;
        --start|--stop|--status)
            ACTION="$1"
            ;;
        -d)
            DURATION="$2"
            shift
            ;;
        -f)
            FILE=",file=$2"
            shift
            ;;
        -i)
            INTERVAL=",interval=$2"
            shift
            ;;
        -b)
            FRAMEBUF=",framebuf=$2"
            shift
            ;;
        -o)
            OUTPUT=",$2"
            shift
            ;;
        [0-9]*)
            PID="$1"
            ;;
        *)
        	echo "Unrecognized option: $1"
        	usage
        	;;
    esac
    shift
done

[[ "$PID" == "" ]] && usage

case $ACTION in
    --start)
        $JATTACH $PID load $PROFILER true start$INTERVAL$FRAMEBUF > /dev/null
        ;;
    --stop)
        $JATTACH $PID load $PROFILER true stop$FILE$OUTPUT > /dev/null
        ;;
    --status)
        $JATTACH $PID load $PROFILER true status > /dev/null
        ;;
    *)
        $JATTACH $PID load $PROFILER true start$INTERVAL$FRAMEBUF > /dev/null
        if [ $? -ne 0 ]; then
            exit 1
        fi
        sleep $DURATION
        $JATTACH $PID load $PROFILER true stop$FILE$OUTPUT > /dev/null
        ;;
esac
