#ifndef TOR_OBSCURE_H
#define TOR_OBSCURE_H

#include <stdint.h>
#include "trunnel.h"
typedef enum{
    obscure_none,
    obscure_later,
    obscure_scheduled,
    obscure_already_scheduled,
    obscure_sent,
} obscure_descision_t;

void obscure_disable_on_channel(channel_t* chan);
#endif