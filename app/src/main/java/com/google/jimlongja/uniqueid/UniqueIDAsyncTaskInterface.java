package com.google.jimlongja.uniqueid;

import java.security.cert.X509Certificate;

public interface UniqueIDAsyncTaskInterface {
    void onComplete(X509Certificate x509cert);
}
