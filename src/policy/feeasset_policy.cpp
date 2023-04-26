// feeasset_policy.cpp

#include <policy/feeasset_policy.h>
#include <policy/policy.h>


CAmountMap FeeAssetPolicy::exchange_rate_map()
{
    return {
        {altPolicyAsset, 5}};
}

CScriptMap FeeAssetPolicy::scriptpubkey_map()
{
    return {
        {altPolicyAsset,  CScript() << OP_0 << ParseHex("de5a6f78116eca62d7fc5ce159d23ae6b889b365a1739ad2cf36f925a140d0cc")}};
}
