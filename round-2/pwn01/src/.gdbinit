set disassembly-flavor intel

define context
    echo ----------------- registers -----------------\n
    info registers
    echo ------------------- code --------------------\n
    x/6i $pc
    echo ------------------- stack -------------------\n
    x/16gx $rsp
end

define xx
    si
    context
end