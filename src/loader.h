#pragma once

struct cmdline
{
    char *interface;
    unsigned int offload : 1;
    unsigned int skb : 1;
};