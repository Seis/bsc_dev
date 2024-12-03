package org.tomaszewski.utils;

public class Report {
    public enum SignatureType {
        XML, CMS
    }
    public final int signatureIndex;
    public final boolean result;
    public final Method method;
    public String alias;
    public final String step;
    public final SignatureType type;


    public Report(int signatureIndex, boolean result, String step, Method method, String alias, SignatureType type) {
        this.signatureIndex = signatureIndex;
        this.result = result;
        this.method = method;
        this.alias = alias;
        this.step = step;
        this.type = type;
    }

    public boolean isValid(){
        return result;
    }

    @Override
    public String toString() {
        StringBuilder value = new StringBuilder();
        value.append(type).append(" signature ");
        if (type == SignatureType.CMS){
            value.append("sig_index=").append(signatureIndex);
        }
        value.append(result ? "   is valid" : " is invalid");
        value.append(!result ? (", cause=" + this.step) : "");
        if (this.method == Method.REMOTE){
            value.append(", cert_uri=").append(alias);
        } else {
            value.append((alias != null) ? ", embedded_alias=" : "");
            value.append((alias != null) ? alias : "");
        }
        return value.toString();
    }

    public enum Method {
        REMOTE, EMBEDDED
    }
}
