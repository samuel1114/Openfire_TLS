package com.sabaothtech;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class HTTPSTrustManager {

    public static SSLContext getSSLContextAllowAll() throws KeyManagementException,
            NoSuchAlgorithmException {
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(
                    X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(
                    X509Certificate[] certs, String authType) {
            }
        }};

        // Create an SSLContext that uses our TrustManager
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAllCerts, new java.security.SecureRandom());
        return context;
    }

    public static SocketFactory allowAllSSL() throws KeyManagementException,
            NoSuchAlgorithmException {
        return getSSLContextAllowAll().getSocketFactory();
    }

    public static SSLContext getSSLContextWithCert() throws Exception {
        // Load CAs from an InputStream
        // (could be from a resource or ByteArrayInputStream or ...)
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream caInput = new FileInputStream("certificate path");
        Certificate ca;
        try {
            ca = cf.generateCertificate(caInput);
            System.out.println(String.format("CA:%s", "ca=" + ((X509Certificate) ca).getSubjectDN()));
        } finally {
            caInput.close();
        }

        // Create a KeyStore containing our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);

        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        // Create an SSLContext that uses our TrustManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        return sslContext;
    }

    public static SocketFactory allowSSLWithCert() throws Exception {
        return getSSLContextWithCert().getSocketFactory();
    }

}

