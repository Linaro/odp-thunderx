TTY=$(readlink -f /proc/self/fd/0)
CONFIG=${CONFIG:-validate.conf}
__get_validation_suite() {
    if [ -f $CONFIG ]; then
        cat $CONFIG|sed -ne 's@^\(^test/validation/\)@\1@p'
    else
        ls test/validation/*/*_main
    fi
}
__get_validation_suite|while read PROG; do
    echo "---------------------------------------------------------"
    echo $PROG
    echo
    if [ -n "$GDB" ]; then
        if [ -n "$GDB_SCRIPT" ] && [ -f "$GDB_SCRIPT" ]; then
            PROG="gdb -x $GDB_SCRIPT --args $PROG"
        else
            PROG="gdb --args $PROG"
        fi
        $PROG < $TTY
    elif [ -n "$SHORT" ]; then
        $PROG 2>&1 | egrep 'Run Summary' -A 4
    else
        $PROG
    fi
done
