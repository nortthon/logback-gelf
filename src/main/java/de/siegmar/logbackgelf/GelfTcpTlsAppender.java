/*
 * Logback GELF - zero dependencies Logback GELF appender library.
 * Copyright (C) 2016 Oliver Siegmar
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

package de.siegmar.logbackgelf;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class GelfTcpTlsAppender extends GelfTcpAppender {

    /**
     * If {@code true}, trust all TLS certificates (even self signed certificates).
     */
    private boolean trustAllCertificates;

    private List<X509Certificate> trustedServerCertificates = new ArrayList<>();

    public boolean isTrustAllCertificates() {
        return trustAllCertificates;
    }

    public void setTrustAllCertificates(final boolean trustAllCertificates) {
        this.trustAllCertificates = trustAllCertificates;
    }

    public void addTrustedServerCertificate(final String trustedServerCertificate)
        throws CertificateException {

        trustedServerCertificates.add(readCert(trustedServerCertificate));
    }

    private X509Certificate readCert(final String cert) throws CertificateException {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(
            new ByteArrayInputStream(cert.getBytes(StandardCharsets.US_ASCII)));
    }

    @Override
    protected SSLSocketFactory initSocketFactory() {
        if (!trustedServerCertificates.isEmpty()) {
            if (trustAllCertificates) {
                throw new IllegalStateException("TrustAllCertificates is not possible when "
                    + "configuring server and/or CA certificates explicitly");
            }

            try {
                final EasyX509TrustManager trustManager = new EasyX509TrustManager();
                trustManager.setTrustedServerCertificates(trustedServerCertificates);

                return configureSslFactory(trustManager);
            } catch (final GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        if (trustAllCertificates) {
            addWarn("Enable trustAllCertificates - don't use this in production!");
            try {
                return configureSslFactory(buildNoopTrustManager());
            } catch (final NoSuchAlgorithmException | KeyManagementException e) {
                throw new IllegalStateException(e);
            }
        }

        return (SSLSocketFactory) SSLSocketFactory.getDefault();
    }

    private SSLSocketFactory configureSslFactory(final TrustManager trustManager)
        throws NoSuchAlgorithmException, KeyManagementException {

        final SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{trustManager}, new SecureRandom());
        return context.getSocketFactory();
    }

    private static TrustManager buildNoopTrustManager() {
        return new X509TrustManager() {
            public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
            }

            public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

}
