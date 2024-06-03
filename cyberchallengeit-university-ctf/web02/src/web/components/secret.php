<?php

function get_flag() 
{
    $base_flag = getenv("FLAG");
    return str_replace("[RANDOM]", '0f2a3ca5', $base_flag);
}