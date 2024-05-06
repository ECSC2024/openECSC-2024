/*
 * Copyright (C) 2006-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <chrono>
using std::cerr;
using std::endl;
using std::ifstream;
using std::ios;
using std::ofstream;

void Usage(char** argv)
{
    cerr << "Usage: " << argv[0] << " input-file output-file [-s]" << endl;
    exit(1);
}

int main(int argc, char** argv)
{
    bool time_probe = false;

    if (argc != 3 && argc != 4)
    {
        Usage(argv);
    }
    char* ifn = argv[1];
    char* ofn = argv[2];

    if (argc == 4)
    {
        if (0 != strcmp(argv[3], "-s"))
        {
            Usage(argv);
        }

        time_probe = true;
    }

    std::chrono::time_point< std::chrono::high_resolution_clock > start, end;

    if (time_probe) start = std::chrono::high_resolution_clock::now();

    ifstream* i = new ifstream(ifn, ios::in | ios::binary);

    if (!i)
    {
        cerr << "Could not open input file " << ifn << endl;
        exit(1);
    }

    ofstream* o = new ofstream(ofn, ios::out | ios::trunc | ios::binary);
    if (!o)
    {
        cerr << "Could not open output file " << ofn << endl;
        exit(1);
    }

    char ch;
    while (i->get(ch))
    {
        *o << ch;
    }
    i->close();
    o->close();

    if (time_probe)
    {
        end                          = std::chrono::high_resolution_clock::now();
        auto time_spent              = std::chrono::duration_cast< std::chrono::microseconds >(end - start);
        unsigned int test_time_msecs = time_spent.count();

        if (time_probe) std::cout << "Iteration delay: " << test_time_msecs << " usec\n";
    }

    exit(0);
}
