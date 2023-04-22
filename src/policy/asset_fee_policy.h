#include <amount.h>
#include <serialize.h>

class AssetFeePolicy
{
  public:
    CAmount GetFee(uint32_t num_bytes) const;
};