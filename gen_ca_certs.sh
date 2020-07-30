#!/bin/sh -e

cd $2

if [ -f certdata.txt ]
then
    perl $1 -qn cert.pem > /dev/null
else
    perl $1 -q cert.pem > /dev/null
fi

cat << EOF > ca_certs.c
#include <sys/types.h>

static const unsigned char arr[] = \\
EOF

grep -v -e ^# -e '^$' cert.pem |
while read x
do
    echo "    \"$x\\\\n\" \\"
done >> ca_certs.c

cat << EOF >> ca_certs.c
;

const unsigned char *ca_certs = arr;
const size_t ca_certs_len = sizeof(arr);
EOF