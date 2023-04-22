#include "deserialize.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include "primitive.h"
#include "unreachable.h"

/* Fetches 'len' 'uint32_t's from 'stream' into 'result'.
 * The bits in each 'uint32_t' are set from the MSB to the LSB and the 'uint32_t's of 'result' are set from 0 up to 'len'.
 * Returns 'SIMPLICITY_ERR_BITSTREAM_EOF' if not enough bits are available ('result' may be modified).
 * Returns 0 if successful.
 *
 * Precondition: uint32_t result[len];
 *               NULL != stream
 */
static int32_t getWord32Array(uint32_t* result, const size_t len, bitstream* stream) {
  for (size_t i = 0; i < len; ++i) {
    /* Due to error codes, readNBits cannot fetch 32 bits at once. Instead we fetch two groups of 16 bits. */
    int32_t bits16 = readNBits(16, stream);
    if (bits16 < 0) return bits16;
    result[i] = (uint32_t)bits16 << 16;
    bits16 = readNBits(16, stream);
    if (bits16 < 0) return bits16;
    result[i] |= (uint32_t)bits16;
  }
  return 0;
}

/* Fetches a 256-bit hash value from 'stream' into 'result'.
 * Returns 'SIMPLICITY_ERR_BITSTREAM_EOF' if not enough bits are available ('result' may be modified).
 * Returns 0 if successful.
 *
 * Precondition: NULL != result
 *               NULL != stream
 */
static int32_t getHash(sha256_midstate* result, bitstream* stream) {
  return getWord32Array(result->s, 8, stream);
}


/* Decode a single node of a Simplicity dag from 'stream' into 'dag'['i'].
 * Returns 'SIMPLICITY_ERR_FAIL_CODE' if the encoding of a fail expression is encountered
 *   (all fail subexpressions ought to have been pruned prior to serialization).
 * Returns 'SIMPLICITY_ERR_STOP_CODE' if the encoding of a stop tag is encountered.
 * Returns 'SIMPLICITY_ERR_HIDDEN' if the decoded node has illegal HIDDEN children.
 * Returns 'SIMPLICITY_ERR_DATA_OUT_OF_RANGE' if the node's child isn't a reference to one of the preceding nodes.
 *                                            or some encoding for a non-existent jet is encountered
 *                                            or the size of a WORD encoding is greater than 2^31 bits.
 * Returns 'SIMPLICITY_ERR_BITSTRING_EOF' if not enough bits are available in the 'stream'.
 * In the above error cases, 'dag' may be modified.
 * Returns 0 if successful.
 *
 * Precondition: dag_node dag[i + 1];
 *               i < 2^31 - 1
 *               NULL != stream
 */

//RANDY_COMMENTED
//Try to read the node in the dag in as a JET or command code(?)
static int32_t decodeNode(dag_node* dag, size_t i, bitstream* stream) {

  //Read 1 bit
  int32_t bit = read1Bit(stream);

  //If the bit is less than 0 then return 0 (like in 'decodeUptoMaxInt' except don't return 1 if 0)
  if (bit < 0) return bit;

  //Set the dag to a 0'd dag node
  dag[i] = (dag_node){0};

  //If the bit is not 0
  if (bit) {
    //Read another bit
    bit = read1Bit(stream);

    //If the bit is less than 0 then return the bit
    if (bit < 0) return bit;

    //If the bit is > 0
    if (bit) {
      //Try and decode a jet from the stream into the dag
      return decodeJet(&dag[i], stream);
    } 
    //If the bit == 0, then don't read jet and instead read WORD
    else {

      //E
      /* Decode WORD. */
      //EE

      //If there is no jet then try to read an int called depth
      int32_t depth = decodeUptoMaxInt(stream);

      //If the dpeth is less than 0 then return
      if (depth < 0) return depth;


      //REVIEW - again with the curly brace after an if-statement
      //If the depth is greater than 32, error out
      if (32 < depth) return SIMPLICITY_ERR_DATA_OUT_OF_RANGE;

      {
        //Read the bit string into a compact value of the dag
        int32_t result = readBitstring(&dag[i].compactValue, (size_t)1 << (depth - 1), stream);
        //If the result is less than 0 then return it (as err?)
        if (result < 0) return result;
      }

      //Set the tag of the dag to a 'WORD'
      dag[i].tag = WORD;

      //Set the target to the depth
      dag[i].targetIx = (size_t)depth;

      //Set the cmr to whatever is returned by 'computeWordCMR'
      dag[i].cmr = computeWordCMR(&dag[i].compactValue, (size_t)(depth - 1));
    }
  } 
  
  //If the first word bit is 0
  else {

    //Read 2 bits from the stream as a code
    int32_t code = readNBits(2, stream);

    //If the code is less than 0 , return the code as error 
    if (code < 0) return code;

    //Get the sub code depending on value of code (could be 1-2 bits)
    int32_t subcode = readNBits(code < 3 ? 2 : 1, stream);

    //Check subcode isnt an error
    if (subcode < 0) return subcode;

    //For j up to '2 - code' (which could be any 2 bit num- so 0-3)
    //Only catches if code is 0 or 1. If 0 will loop twice, if 1 loop once
    for (int32_t j = 0; j < 2 - code; ++j) {
      //Decode an int
      int32_t ix = decodeUptoMaxInt(stream);

      //Make sure ix is valid
      if (ix < 0) return ix;

      //If dag node index 'i' is less than ix, fail (i must be greater than ix )
      if (i < (uint32_t)ix) return SIMPLICITY_ERR_DATA_OUT_OF_RANGE;

      //Set the 'code' index of the dag's child to (i - ix)
      dag[i].child[j] = i - (uint32_t)ix;
    }

    //Switch the code read
    switch (code) {
    
    //If the code is 0
     case 0:
      //switch the subcode
      switch (subcode) {
        //If subcode is 0, the tag of the dag is composition 
       case 0: dag[i].tag = COMP; break;
       //If subcode iss 1, then the tag might be ASSERTL or R, or CASE if neither
       case 1:
        dag[i].tag = (HIDDEN == dag[dag[i].child[0]].tag) ? ASSERTR
                   : (HIDDEN == dag[dag[i].child[1]].tag) ? ASSERTL
                   : CASE;
        break;
      
        //If the case is 2 then its a pair
       case 2: dag[i].tag = PAIR; break;

       //If the case is 3 then the tag is disconnect
       case 3: dag[i].tag = DISCONNECT; break;
      }
      break;

      //If the code is 1
     case 1:
     //The subcode could make the DAG one of INJL, INJR, TAKE, or DROP (all act on pairs)
      switch (subcode) {
       case 0: dag[i].tag = INJL; break;
       case 1: dag[i].tag = INJR; break;
       case 2: dag[i].tag = TAKE; break;
       case 3: dag[i].tag = DROP; break;
      }
      break;
    
    //If the code is 2
     case 2:
     //The subcode should make the dag tag IDEN or UNIT (or make it fail)
      switch (subcode) {
       case 0: dag[i].tag = IDEN; break;
       case 1: dag[i].tag = UNIT; break;
       case 2: return SIMPLICITY_ERR_FAIL_CODE;
       case 3: return SIMPLICITY_ERR_STOP_CODE;
      }
      break;

    //If tthe code is 3
     case 3:
     //The subcode can make the dag HIDDEN or WITNESS
      switch (subcode) {
       case 0:
        dag[i].tag = HIDDEN;
        return getHash(&(dag[i].cmr), stream);
       case 1:
        dag[i].tag = WITNESS;
        break;
      }
      break;
    }

    //E
    /* Verify that there are no illegal HIDDEN children. */
    //EE

    //For all of j up to 2- code
    for (int32_t j = 0; j < 2 - code; ++j) {
        //If the child of dag i has a hidden tag, and the tag of dag i is not ASSERTL or ASSERTR then error out
       if (HIDDEN == dag[dag[i].child[j]].tag && dag[i].tag != (j ? ASSERTL : ASSERTR)) return SIMPLICITY_ERR_HIDDEN;
    }

    //Compute the merkle root of simplicity dag
    computeCommitmentMerkleRoot(dag, i);
  }

  //return 0
  return 0;
}

/* Decode a Simplicity DAG consisting of 'len' nodes from 'stream' into 'dag'.
 * Returns 'SIMPLICITY_ERR_DATA_OUT_OF_RANGE' if some node's child isn't a reference to one of the preceding nodes.
 * Returns 'SIMPLICITY_ERR_FAIL_CODE' if the encoding of a fail expression is encountered
 *   (all fail subexpressions ought to have been pruned prior to deserialization).
 * Returns 'SIMPLICITY_ERR_STOP_CODE' if the encoding of a stop tag is encountered.
 * Returns 'SIMPLICITY_ERR_HIDDEN' if there are illegal HIDDEN children in the DAG.
 * Returns 'SIMPLICITY_ERR_BITSTRING_EOF' if not enough bits are available in the 'stream'.
 * In the above error cases, 'dag' may be modified.
 * Returns 0 if successful.
 *
 * Precondition: dag_node dag[len];
 *               len < 2^31
 *               NULL != stream
 */

//RANDY_COMMENTED
//Tries to read in the dag from the stream and calls the enumerator on it with the combinator 'census' (which increments the count of combinators on census)
static int32_t decodeDag(dag_node* dag, const size_t len, combinator_counters* census, bitstream* stream) {

  //For the dag length
  for (size_t i = 0; i < len; ++i) {
    //Decode the node and try to parse the error
    int32_t err = decodeNode(dag, i, stream);

    //if error is less than 0 then return
    if (err < 0) return err;

    //otherwise call the enumerator with the combinator and tag of the just read in dag
    enumerator(census, dag[i].tag);
  }

  //Return 0
  return 0;
}

/* Decode a length-prefixed Simplicity DAG from 'stream'.
 * Returns 'SIMPLICITY_ERR_DATA_OUT_OF_RANGE' the length prefix's value is too large.
 * Returns 'SIMPLICITY_ERR_DATA_OUT_OF_RANGE' if some node's child isn't a reference to one of the preceding nodes.
 * Returns 'SIMPLICITY_ERR_FAIL_CODE' if the encoding of a fail expression is encountered
 *  (all fail subexpressions ought to have been pruned prior to deserialization).
 * Returns 'SIMPLICITY_ERR_STOP_CODE' if the encoding of a stop tag is encountered.
 * Returns 'SIMPLICITY_ERR_HIDDEN' if there are illegal HIDDEN children in the DAG.
 * Returns 'SIMPLICITY_ERR_BITSTRING_EOF' if not enough bits are available in the 'stream'.
 * Returns 'SIMPLICITY_ERR_MALLOC' if malloc fails.
 * In the above error cases, '*dag' is set to NULL.
 * If successful, returns a positive value equal to the length of an allocated array of (*dag).
 *
 * Precondition: NULL != dag
 *               NULL != stream
 *
 * Postcondition: if the return value of the function is positive
 *                  then (dag_node (*dag)[return_value] and '*dag' is a well-formed dag without witness data);
 *                '*census' contains a tally of the different tags that occur in 'dag' when the return value
 *                          of the function is positive and when NULL != census;
 *                NULL == *dag when the return value is negative.
 */


//RANDY_COMMENTED
//Tries to allocate the space needed for the dag from the bitstream, creates space for a dag and tries to load it in (with 'decodeDag'),
//and finally will either error out if dag is invalid or return the dag length. The dat arg should be null btw, but
//its set to it at beginning of this function anyway
int32_t decodeMallocDag(dag_node** dag, combinator_counters* census, bitstream* stream) {
  //Set the DAG pointer passed in to null
  *dag = NULL;

  //Decode as much as we can from the bitstream into an int
  int32_t dagLen = decodeUptoMaxInt(stream);

  //If the dag lentgth is negative then return
  //REVIEW - no error?
  if (dagLen <= 0) return dagLen;

  //E
  /* :TODO: a consensus parameter limiting the maximum length of a DAG needs to be enforced here */
  //EE

  //if the max long value divided by the size of the dag node in argument is smaller than the dag length
  //then return an error
  if (PTRDIFF_MAX / sizeof(dag_node) < (size_t)dagLen) return SIMPLICITY_ERR_DATA_OUT_OF_RANGE;

  //Allocate the size for each dag_node (dagLen is the size of each)
  *dag = malloc((size_t)dagLen * sizeof(dag_node));

  //If we can't allocate it then error out
  if (!*dag) return SIMPLICITY_ERR_MALLOC;

  //if census then set the census to a combinator counters initialized to 0
  if (census) *census = (combinator_counters){0};

  //Try and decode the dag using the dag, the daglength, the combinator counter census, and the bitstream
  int32_t err = decodeDag(*dag, (size_t)dagLen, census, stream);

  //if the error is less than 0 AND the canonicalOrder can't be verified, then error out
  if (0 <= err && !verifyCanonicalOrder(*dag, (size_t)(dagLen))) {
    err = SIMPLICITY_ERR_DATA_OUT_OF_ORDER;
  }

  //if the erorr is less than 0
  if (err < 0) {
    //free the dag and set to null befor returning null
    free(*dag);
    *dag = NULL;
    return err;
  } else {

    //otherwise return the dagLength
    return dagLen;
  }
}

/* Decode a string of up to 2^31 - 1 bits from 'stream'.
 * This is the format in which the data for 'WITNESS' nodes are encoded.
 * Returns 'SIMPLICITY_ERR_DATA_OUT_OF_RANGE' if the encoded string of bits exceeds this decoder's limits.
 * Returns 'SIMPLICITY_ERR_BITSTRING_EOF' if not enough bits are available in the 'stream'.
 * If successful, '*witness' is set to the decoded bitstring,
 *                and 0 is returned.
 *
 * If an error is returned '*witness' might be modified.
 *
 * Precondition: NULL != witness;
 *               NULL != stream;
 */
int32_t decodeWitnessData(bitstring* witness, bitstream* stream) {
  int32_t witnessLen = read1Bit(stream);
  if (witnessLen < 0) return witnessLen;
  if (0 < witnessLen) witnessLen = decodeUptoMaxInt(stream);
  if (witnessLen < 0) return witnessLen;

  return readBitstring(witness, (size_t)witnessLen, stream);
}
