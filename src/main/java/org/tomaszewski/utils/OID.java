package org.tomaszewski.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class OID {
    public static final ASN1ObjectIdentifier REMOTE_CERT = new ASN1ObjectIdentifier("2.2.1.6");
    public static final ASN1ObjectIdentifier AIA = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1");
    public static final ASN1ObjectIdentifier CA_ISSUER = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.2");
    public static final ASN1ObjectIdentifier ALIAS_UNSIGNED_ATTRIBUTE = new ASN1ObjectIdentifier("2.2.2.2.2.2.2.2");
}
