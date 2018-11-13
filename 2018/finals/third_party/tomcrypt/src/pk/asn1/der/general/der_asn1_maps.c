/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
  @file der_asn1_maps.c
  ASN.1 DER, a collection of maps to convert between different representations, Steffen Jaeckel
*/

#ifdef LTC_DER

/**
  A Map from ltc_asn1_type to the regularly used ASN.1 identifier
*/
const int der_asn1_type_to_identifier_map[] =
{
     /*  0 */
 -1, /* LTC_ASN1_EOL, */
  1, /* LTC_ASN1_BOOLEAN, */
  2, /* LTC_ASN1_INTEGER, */
  2, /* LTC_ASN1_SHORT_INTEGER, */
  3, /* LTC_ASN1_BIT_STRING, */
     /*  5 */
  4, /* LTC_ASN1_OCTET_STRING, */
  5, /* LTC_ASN1_NULL, */
  6, /* LTC_ASN1_OBJECT_IDENTIFIER, */
 22, /* LTC_ASN1_IA5_STRING, */
 19, /* LTC_ASN1_PRINTABLE_STRING, */
     /* 10 */
 12, /* LTC_ASN1_UTF8_STRING, */
 23, /* LTC_ASN1_UTCTIME, */
 -1, /* LTC_ASN1_CHOICE, */
 48, /* LTC_ASN1_SEQUENCE, */
 49, /* LTC_ASN1_SET, */
     /* 15 */
 49, /* LTC_ASN1_SETOF, */
  3, /* LTC_ASN1_RAW_BIT_STRING, */
 20, /* LTC_ASN1_TELETEX_STRING, */
 24, /* LTC_ASN1_GENERALIZEDTIME, */
 -1, /* LTC_ASN1_CUSTOM_TYPE, */
};
const unsigned long der_asn1_type_to_identifier_map_sz = sizeof(der_asn1_type_to_identifier_map)/sizeof(der_asn1_type_to_identifier_map[0]);

/**
  A Map from the ASN.1 Class to its string
*/
const char* der_asn1_class_to_string_map[] =
{
  "UNIVERSAL",
  "APPLICATION",
  "CONTEXT-SPECIFIC",
  "PRIVATE",
};
const unsigned long der_asn1_class_to_string_map_sz = sizeof(der_asn1_class_to_string_map)/sizeof(der_asn1_class_to_string_map[0]);

/**
  A Map from the ASN.1 P/C-bit to its string
*/
const char* der_asn1_pc_to_string_map[] =
{
  "PRIMITIVE",
  "CONSTRUCTED",
};
const unsigned long der_asn1_pc_to_string_map_sz = sizeof(der_asn1_pc_to_string_map)/sizeof(der_asn1_pc_to_string_map[0]);

/**
  A Map from the ASN.1 tag to its string
*/
const char* der_asn1_tag_to_string_map[] =
{
  "Reserved for use by the encoding rules",
  "Boolean type",
  "Integer type",
  "Bitstring type",
  "Octetstring type",
  "Null type",
  "Object identifier type",
  "Object descriptor type",
  "External type and Instance-of type",
  "Real type",
  "Enumerated type",
  "Embedded-pdv type",
  "UTF8String type",
  "Relative object identifier type",
  "The time type",
  "Reserved for future editions of this Recommendation | International Standard",
  "Sequence and Sequence-of types",
  "Set and Set-of types",
  "NumericString type",
  "PrintableString type",
  "TeletexString (T61String) type",
  "VideotexString type",
  "IA5String type",
  "UTCTime type",
  "GeneralizedTime type",
  "GraphicString type",
  "VisibleString (ISO646String) type",
  "GeneralString type",
  "UniversalString type",
  "UnrestrictedCharacterString type",
  "BMPString type",
  "Date type",
  "TimeOfDay type",
  "DateTime type",
  "Duration type",
  "OID internationalized resource identifier type",
  "Relative OID internationalized resource identifier type",
};
const unsigned long der_asn1_tag_to_string_map_sz = sizeof(der_asn1_tag_to_string_map)/sizeof(der_asn1_tag_to_string_map[0]);

/**
  A Map from ASN.1 Tags to ltc_asn1_type
*/
const ltc_asn1_type der_asn1_tag_to_type_map[] =
{
  /*  0 */
  LTC_ASN1_EOL,               /* Reserved for use by the encoding rules */
  LTC_ASN1_BOOLEAN,           /* Boolean type */
  LTC_ASN1_INTEGER,           /* Integer type */
  LTC_ASN1_BIT_STRING,        /* Bitstring type */
  LTC_ASN1_OCTET_STRING,      /* Octetstring type */
  /*  5 */
  LTC_ASN1_NULL,              /* Null type */
  LTC_ASN1_OBJECT_IDENTIFIER, /* Object identifier type */
  LTC_ASN1_CUSTOM_TYPE,      /* Object descriptor type */
  LTC_ASN1_CUSTOM_TYPE,      /* External type and Instance-of type */
  LTC_ASN1_CUSTOM_TYPE,      /* Real type */
  /* 10 */
  LTC_ASN1_CUSTOM_TYPE,      /* Enumerated type */
  LTC_ASN1_CUSTOM_TYPE,      /* Embedded-pdv type */
  LTC_ASN1_UTF8_STRING,       /* UTF8String type */
  LTC_ASN1_CUSTOM_TYPE,      /* Relative object identifier type */
  LTC_ASN1_CUSTOM_TYPE,      /* The time type */
  /* 15 */
  LTC_ASN1_EOL,               /* Reserved for future editions of this Recommendation | International Standard */
  LTC_ASN1_SEQUENCE,          /* Sequence and Sequence-of types */
  LTC_ASN1_SET,               /* Set and Set-of types */
  LTC_ASN1_CUSTOM_TYPE,      /* NumericString types */
  LTC_ASN1_PRINTABLE_STRING,  /* PrintableString types */
  /* 20 */
  LTC_ASN1_TELETEX_STRING,    /* TeletexString (T61String) types */
  LTC_ASN1_CUSTOM_TYPE,      /* VideotexString types */
  LTC_ASN1_IA5_STRING,        /* IA5String types */
  LTC_ASN1_UTCTIME,           /* UTCTime types */
  LTC_ASN1_GENERALIZEDTIME,   /* GeneralizedTime types */
  /* 25 */
  LTC_ASN1_CUSTOM_TYPE,      /* GraphicString types */
  LTC_ASN1_CUSTOM_TYPE,      /* VisibleString (ISO646String) types */
  LTC_ASN1_CUSTOM_TYPE,      /* GeneralString types */
  LTC_ASN1_CUSTOM_TYPE,      /* UniversalString types */
  LTC_ASN1_CUSTOM_TYPE,      /* UnrestrictedCharacterString types */
  /* 30 */
  LTC_ASN1_CUSTOM_TYPE,      /* BMPString types */
};
const unsigned long der_asn1_tag_to_type_map_sz = sizeof(der_asn1_tag_to_type_map)/sizeof(der_asn1_tag_to_type_map[0]);

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
