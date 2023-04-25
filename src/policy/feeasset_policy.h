#ifndef RANDY_FEE_ASSET_H
#define RANDY_FEE_ASSET_H

#include <amount.h>
#include <asset.h>
#include <script/script.h>
#include <serialize.h>
#include <string.h>

typedef std::map<CAsset, CScript> CScriptMap;
class FeeAssetPolicy {
  public:
    static CAmountMap exchange_rate_map();
    static CScriptMap scriptpubkey_map();
};

#endif