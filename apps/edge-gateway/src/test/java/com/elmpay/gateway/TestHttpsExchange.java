package com.elmpay.gateway;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpPrincipal;
import com.sun.net.httpserver.HttpsExchange;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;
import javax.net.ssl.SSLSession;

/** Minimal HTTPS exchange whose peer identity cannot be supplied through request headers. */
final class TestHttpsExchange extends HttpsExchange {
    private final Headers requestHeaders;
    private final Headers responseHeaders = new Headers();
    private final SSLSession session;
    private InputStream requestBody = new ByteArrayInputStream(new byte[0]);
    private OutputStream responseBody = new ByteArrayOutputStream();

    TestHttpsExchange(Headers requestHeaders, byte[] peerCertificateDer) {
        this(requestHeaders, new EncodedX509Certificate(peerCertificateDer));
    }

    TestHttpsExchange(Headers requestHeaders, X509Certificate peer) {
        this.requestHeaders = requestHeaders;
        this.session = (SSLSession) Proxy.newProxyInstance(SSLSession.class.getClassLoader(),
                new Class<?>[] {SSLSession.class}, (proxy, method, arguments) -> {
                    if ("getPeerCertificates".equals(method.getName())) {
                        return new Certificate[] {peer};
                    }
                    if ("getProtocol".equals(method.getName())) {
                        return "TLSv1.3";
                    }
                    Class<?> type = method.getReturnType();
                    if (!type.isPrimitive()) {
                        return null;
                    }
                    if (type == boolean.class) {
                        return false;
                    }
                    if (type == byte.class) {
                        return (byte) 0;
                    }
                    if (type == short.class) {
                        return (short) 0;
                    }
                    if (type == int.class) {
                        return 0;
                    }
                    if (type == long.class) {
                        return 0L;
                    }
                    if (type == float.class) {
                        return 0.0F;
                    }
                    if (type == double.class) {
                        return 0.0D;
                    }
                    if (type == char.class) {
                        return '\0';
                    }
                    throw new AssertionError("unsupported primitive return type");
                });
    }

    @Override public SSLSession getSSLSession() { return session; }
    @Override public Headers getRequestHeaders() { return requestHeaders; }
    @Override public Headers getResponseHeaders() { return responseHeaders; }
    @Override public URI getRequestURI() { return URI.create("https://edge.example/v1/test"); }
    @Override public String getRequestMethod() { return "GET"; }
    @Override public HttpContext getHttpContext() { return null; }
    @Override public void close() { }
    @Override public InputStream getRequestBody() { return requestBody; }
    @Override public OutputStream getResponseBody() { return responseBody; }
    @Override public void sendResponseHeaders(int responseCode, long responseLength) { }
    @Override public InetSocketAddress getRemoteAddress() { return new InetSocketAddress(443); }
    @Override public int getResponseCode() { return -1; }
    @Override public InetSocketAddress getLocalAddress() { return new InetSocketAddress(8443); }
    @Override public String getProtocol() { return "HTTP/1.1"; }
    @Override public Object getAttribute(String name) { return null; }
    @Override public void setAttribute(String name, Object value) { }
    @Override public void setStreams(InputStream input, OutputStream output) {
        requestBody = input;
        responseBody = output;
    }
    @Override public HttpPrincipal getPrincipal() { return null; }

    @SuppressWarnings("deprecation")
    private static final class EncodedX509Certificate extends X509Certificate {
        private static final long serialVersionUID = 1L;
        private final byte[] encoded;

        private EncodedX509Certificate(byte[] encoded) { this.encoded = encoded.clone(); }
        @Override public void checkValidity() { }
        @Override public void checkValidity(Date date) { }
        @Override public int getVersion() { return 3; }
        @Override public BigInteger getSerialNumber() { return BigInteger.ONE; }
        @Override public Principal getIssuerDN() { return () -> "CN=test-ca"; }
        @Override public Principal getSubjectDN() { return () -> "CN=test-client"; }
        @Override public Date getNotBefore() { return new Date(0L); }
        @Override public Date getNotAfter() { return new Date(Long.MAX_VALUE); }
        @Override public byte[] getTBSCertificate() { return encoded.clone(); }
        @Override public byte[] getSignature() { return new byte[0]; }
        @Override public String getSigAlgName() { return "NONE"; }
        @Override public String getSigAlgOID() { return "0.0"; }
        @Override public byte[] getSigAlgParams() { return null; }
        @Override public boolean[] getIssuerUniqueID() { return null; }
        @Override public boolean[] getSubjectUniqueID() { return null; }
        @Override public boolean[] getKeyUsage() { return null; }
        @Override public int getBasicConstraints() { return -1; }
        @Override public byte[] getEncoded() { return encoded.clone(); }
        @Override public void verify(PublicKey key) { }
        @Override public void verify(PublicKey key, String provider) { }
        @Override public String toString() { return "test X.509 certificate"; }
        @Override public PublicKey getPublicKey() { return null; }
        @Override public Set<String> getCriticalExtensionOIDs() { return Set.of(); }
        @Override public Set<String> getNonCriticalExtensionOIDs() { return Set.of(); }
        @Override public byte[] getExtensionValue(String oid) { return null; }
        @Override public boolean hasUnsupportedCriticalExtension() { return false; }
    }
}
