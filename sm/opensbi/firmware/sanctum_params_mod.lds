
/* 64 Bytes : security monitor's signature by device */
PROVIDE( sanctum_CDI = . );
. += 0x40;

/* 32 Bytes : security monitor's signature by device */
PROVIDE( sanctum_ECASM_pk = . );
. += 0x40;

/* 64 Bytes : security monitor's signature by device */
PROVIDE( test = . );
. += 0x40;

/* 64 Bytes : security monitor's signature by device */
PROVIDE( sanctum_device_root_key_pub = . );
. += 0x40;

/* 512 Bytes : security monitor's signature by device */
PROVIDE( sanctum_cert_sm = . );
. += 0x200;

/* 512 Bytes : security monitor's signature by device */
PROVIDE( sanctum_cert_root = . );
. += 0x200;

/* 512 Bytes : security monitor's signature by device */
PROVIDE( sanctum_cert_man = . );
. += 0x200;

/* 4 Byte : security monitor's signature by device */
PROVIDE( sanctum_length_cert = . );
. += 0x04;

/* 4 Byte : security monitor's signature by device */
PROVIDE( sanctum_length_cert_root = . );
. += 0x04;

/* 4 Byte : security monitor's signature by device */
PROVIDE( sanctum_length_cert_man = . );
. += 0x04;







