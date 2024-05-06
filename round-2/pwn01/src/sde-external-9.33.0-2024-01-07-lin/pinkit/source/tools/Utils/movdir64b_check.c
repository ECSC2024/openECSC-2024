/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>

int ProcessorSupportsMovdir64b();

int main()
{
    if (ProcessorSupportsMovdir64b())
    {
        printf("Yes\n");
    }
    else
    {
        printf("No\n");
    }
    return 0;
}
