package org.tomaszewski.utils;

import java.security.cert.X509Certificate;

public class MyCertificate {
    public final X509Certificate cert;
    public final String uri;

    public MyCertificate(X509Certificate cert, String uri){
        this.uri = uri;
        this.cert = cert;
    }
}
