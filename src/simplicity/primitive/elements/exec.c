#include <simplicity/elements/exec.h>

#include <stdlib.h>
#include <stdalign.h>
#include <string.h>
#include "primitive.h"
#include "../../deserialize.h"
#include "../../eval.h"
#include "../../typeInference.h"

//E
/* Deserialize a Simplicity 'program' and execute it in the environment of the 'ix'th input of 'tx' with `taproot`.
 * If program isn't a proper encoding of a Simplicity program, including its 'program_len', '*success' is set to false.
 * If 'amr != NULL' and the annotated Merkle root of the decoded expression doesn't match 'amr' then '*success' is set to false.
 * Otherwise evaluation proceeds and '*success' is set to the result of evaluation.
 * If 'imr != NULL' and '*success' is set to true, then the identity Merkle root of the decoded expression is written to 'imr'.
 * Otherwise if 'imr != NULL' then 'imr' may or may not be written to.
 *
 * If at any time there is a transient error, such as malloc failing then 'false' is returned, and 'success' may be modified.
 * Otherwise, 'true' is returned.
 *
 * Precondition: NULL != success;
 *               NULL != imr implies unsigned char imr[32]
 *               NULL != tx;
 *               NULL != taproot;
 *               unsigned char genesisBlockHash[32]
 *               NULL != amr implies unsigned char amr[32]
 *               unsigned char program[program_len]
 */
//EE

extern bool elements_simplicity_execSimplicity( bool* success, unsigned char* imr
                                              , const transaction* tx, uint_fast32_t ix, const tapEnv* taproot
                                              , const unsigned char* genesisBlockHash
                                              , const unsigned char* amr
                                              , const unsigned char* program, size_t program_len) {
  if (!success || !tx || !taproot || !program) return false;

  //Initialize a bool 'result'
  bool result;

  //Create counters
  combinator_counters census;

  //Create a dag node pointer
  dag_node* dag;

  //Create a bitstring for the witness, which is a struct with char/byte allocation, length, and offset
  bitstring witness;

  //Declare the dag length
  int32_t dag_len;

  //Declare some mid state shas for amr and genesis
  sha256_midstate amr_hash, genesis_hash;

  //If the amr is present, sha256 midstate into the amr_hash
  if (amr) sha256_toMidstate(amr_hash.s, amr);

  //Unconditionally sha256_toMidstate the genesis hash
  sha256_toMidstate(genesis_hash.s, genesisBlockHash);
  

  {
    //Iniitialize bitstream from the program and program len
    bitstream stream = initializeBitstream(program, program_len);

    //Decode the dag and get its length with dag len
    dag_len = decodeMallocDag(&dag, &census, &stream);

    //If dag len is less than 0
    if (dag_len < 0) {
      //Success is false
      *success = false;
      //FAIL
      return PERMANENT_FAILURE(dag_len);
    }

    //Decode witness data from the bitstream
    int32_t err = decodeWitnessData(&witness, &stream);

    //If the error is less than 0
    if (err < 0) {
      //Return a failure
      *success = false;
      result = PERMANENT_FAILURE(err);
    } else {
      //Otherwise try and close the bitstream
      *success = closeBitstream(&stream);
      result = true;
    }
  }
  //CHECKPOINT

  if (*success) {
    *success = 0 == memcmp(taproot->scriptCMR.s, dag[dag_len-1].cmr.s, sizeof(uint32_t[8]));
    if (*success) {
      type* type_dag;
      result = mallocTypeInference(&type_dag, dag, (size_t)dag_len, &census);
      *success = result && type_dag && 0 == dag[dag_len-1].sourceType && 0 == dag[dag_len-1].targetType
              && fillWitnessData(dag, type_dag, (size_t)dag_len, witness);
      if (*success) {
        sha256_midstate* imr_buf = (size_t)dag_len <= SIZE_MAX / sizeof(sha256_midstate)
                                 ? malloc((size_t)dag_len * sizeof(sha256_midstate))
                                 : NULL;
        bool noDupsCheck;
        result = imr_buf && verifyNoDuplicateIdentityRoots(&noDupsCheck, imr_buf, dag, type_dag, (size_t)dag_len);
        *success = result && noDupsCheck;
        if (*success && imr) sha256_fromMidstate(imr, imr_buf[dag_len-1].s);
        free(imr_buf);
      }
      if (*success && amr) {
        analyses *analysis = (size_t)dag_len <= SIZE_MAX / sizeof(analyses)
                           ? malloc((size_t)dag_len * sizeof(analyses))
                           : NULL;
        if (analysis) {
          computeAnnotatedMerkleRoot(analysis, dag, type_dag, (size_t)dag_len);
          *success = 0 == memcmp(amr_hash.s, analysis[dag_len-1].annotatedMerkleRoot.s, sizeof(uint32_t[8]));
        } else {
          //E
          /* malloc failed which counts as a transient error. */
          //EE
          *success = result = false;
        }
        free(analysis);
      }
      if (*success) {
        //Build a 'txEnv'
        txEnv env = build_txEnv(tx, taproot, &genesis_hash, ix);

        //Evaluate the program using the txEnv
        result = evalTCOProgram(success, dag, type_dag, (size_t)dag_len, &env);
      }
      free(type_dag);
    }
  }

  free(dag);
  return result;
}
