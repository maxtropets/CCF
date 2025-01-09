/* ==========================================================================
 * err_to_str.c -- strings names for errors
 *
 * Copyright (c) 2020, Patrick Uiterwijk. All rights reserved.
 * Copyright (c) 2020,2024, Laurence Lundblade.
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in file named "LICENSE"
 *
 * Created on 3/21/20
 * ========================================================================== */

#include "qcbor/qcbor_common.h"
#include <string.h>

#define ERR_TO_STR_CASE(errpart) case errpart: return #errpart;


const char *
qcbor_err_to_str(const QCBORError uErr) {
   switch (uErr) {
   ERR_TO_STR_CASE(QCBOR_SUCCESS)
   ERR_TO_STR_CASE(QCBOR_ERR_BUFFER_TOO_SMALL)
   ERR_TO_STR_CASE(QCBOR_ERR_ENCODE_UNSUPPORTED)
   ERR_TO_STR_CASE(QCBOR_ERR_BUFFER_TOO_LARGE)
   ERR_TO_STR_CASE(QCBOR_ERR_ARRAY_NESTING_TOO_DEEP)
   ERR_TO_STR_CASE(QCBOR_ERR_CLOSE_MISMATCH)
   ERR_TO_STR_CASE(QCBOR_ERR_ARRAY_TOO_LONG)
   ERR_TO_STR_CASE(QCBOR_ERR_TOO_MANY_CLOSES)
   ERR_TO_STR_CASE(QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN)
   ERR_TO_STR_CASE(QCBOR_ERR_OPEN_BYTE_STRING)
   ERR_TO_STR_CASE(QCBOR_ERR_CANNOT_CANCEL)
   ERR_TO_STR_CASE(QCBOR_ERR_BAD_TYPE_7)
   ERR_TO_STR_CASE(QCBOR_ERR_EXTRA_BYTES)
   ERR_TO_STR_CASE(QCBOR_ERR_UNSUPPORTED)
   ERR_TO_STR_CASE(QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED)
   ERR_TO_STR_CASE(QCBOR_ERR_BAD_INT)
   ERR_TO_STR_CASE(QCBOR_ERR_INDEFINITE_STRING_CHUNK)
   ERR_TO_STR_CASE(QCBOR_ERR_HIT_END)
   ERR_TO_STR_CASE(QCBOR_ERR_BAD_BREAK)
   ERR_TO_STR_CASE(QCBOR_ERR_INPUT_TOO_LARGE)
   ERR_TO_STR_CASE(QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP)
   ERR_TO_STR_CASE(QCBOR_ERR_ARRAY_DECODE_TOO_LONG)
   ERR_TO_STR_CASE(QCBOR_ERR_STRING_TOO_LONG)
   ERR_TO_STR_CASE(QCBOR_ERR_BAD_EXP_AND_MANTISSA)
   ERR_TO_STR_CASE(QCBOR_ERR_NO_STRING_ALLOCATOR)
   ERR_TO_STR_CASE(QCBOR_ERR_STRING_ALLOCATE)
   ERR_TO_STR_CASE(QCBOR_ERR_MAP_LABEL_TYPE)
   ERR_TO_STR_CASE(QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT)
   ERR_TO_STR_CASE(QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED)
   ERR_TO_STR_CASE(QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED)
   ERR_TO_STR_CASE(QCBOR_ERR_TAGS_DISABLED)
   ERR_TO_STR_CASE(QCBOR_ERR_TOO_MANY_TAGS)
   ERR_TO_STR_CASE(QCBOR_ERR_UNEXPECTED_TYPE)
   ERR_TO_STR_CASE(QCBOR_ERR_DUPLICATE_LABEL)
   ERR_TO_STR_CASE(QCBOR_ERR_MEM_POOL_SIZE)
   ERR_TO_STR_CASE(QCBOR_ERR_INT_OVERFLOW)
   ERR_TO_STR_CASE(QCBOR_ERR_DATE_OVERFLOW)
   ERR_TO_STR_CASE(QCBOR_ERR_EXIT_MISMATCH)
   ERR_TO_STR_CASE(QCBOR_ERR_NO_MORE_ITEMS)
   ERR_TO_STR_CASE(QCBOR_ERR_LABEL_NOT_FOUND)
   ERR_TO_STR_CASE(QCBOR_ERR_NUMBER_SIGN_CONVERSION)
   ERR_TO_STR_CASE(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW)
   ERR_TO_STR_CASE(QCBOR_ERR_MAP_NOT_ENTERED)
   ERR_TO_STR_CASE(QCBOR_ERR_CALLBACK_FAIL)
   ERR_TO_STR_CASE(QCBOR_ERR_FLOAT_DATE_DISABLED)
   ERR_TO_STR_CASE(QCBOR_ERR_HALF_PRECISION_DISABLED)
   ERR_TO_STR_CASE(QCBOR_ERR_HW_FLOAT_DISABLED)
   ERR_TO_STR_CASE(QCBOR_ERR_FLOAT_EXCEPTION)
   ERR_TO_STR_CASE(QCBOR_ERR_ALL_FLOAT_DISABLED)
   ERR_TO_STR_CASE(QCBOR_ERR_RECOVERABLE_BAD_TAG_CONTENT)
   ERR_TO_STR_CASE(QCBOR_ERR_CANNOT_ENTER_ALLOCATED_STRING)

   default:
      if(uErr >= QCBOR_ERR_FIRST_USER_DEFINED && uErr <= QCBOR_ERR_LAST_USER_DEFINED) {
         /* Static buffer is not thread safe, but this is only a diagnostic */
         static char buf[20];
         strcpy(buf, "USER_DEFINED_");
         size_t uEndOffset = strlen(buf);
         buf[uEndOffset]   = (char)(uErr/100 + '0');
         buf[uEndOffset+1] = (char)(((uErr/10) % 10) + '0');
         buf[uEndOffset+2] = (char)((uErr % 10 )+ '0');
         buf[uEndOffset+3] = '\0';
         return buf;

      } else {
         return "Unidentified QCBOR error";
      }
   }
}
