/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.remoting3.proxy;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Random;

/**
 * Algorithm for computing proxy auth response of "Digest" authorization scheme.
 *
 * @author <a href="markus.uhr@immopac.ch">Markus Uhr</a>
 */
public class DigestProxyAuthResponse implements ProxyAuthResponse {

    private static final Random rnd = new Random();

    private static final char[] HEXCHARS = new char[] {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private final Charset charset;

    public DigestProxyAuthResponse() {
        this(StandardCharsets.UTF_8);
    }

    public DigestProxyAuthResponse(Charset charset) {
        this.charset = charset;
    }

    private static String bytesToHex(byte[] buffer) {
        int n = buffer.length;
        char[] result = new char[2*n];
        for (int j=0, k=0; j<n; j++) {
            int v = buffer[j] & 0xFF;
            result[k++] = HEXCHARS[v >> 4];
            result[k++] = HEXCHARS[v & 0x0F];
        }
        return new String(result);
    }

    private static String intToHex(int v) {
        char[] result = new char[8];
        result[7] = HEXCHARS[v & 0x0F];
        v >>= 4;
        result[6] = HEXCHARS[v & 0x0F];
        v >>= 4;
        result[5] = HEXCHARS[v & 0x0F];
        v >>= 4;
        result[4] = HEXCHARS[v & 0x0F];
        v >>= 4;
        result[3] = HEXCHARS[v & 0x0F];
        v >>= 4;
        result[2] = HEXCHARS[v & 0x0F];
        v >>= 4;
        result[1] = HEXCHARS[v & 0x0F];
        v >>= 4;
        result[0] = HEXCHARS[v & 0x0F];
        return new String(result);
    }

    private String digest(String username, String password, String realm, String nonce, String method, String uri, String qop, String nc, String cnonce) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance("MD5");
        byte col = 58; // ":"
        // compute HA1
        hash.update(username.getBytes(this.charset));
        hash.update(col);
        hash.update(realm.getBytes(this.charset));
        hash.update(col);
        hash.update(password.getBytes(this.charset));
        String ha1 = bytesToHex(hash.digest());
        // compute HA2
        hash.reset();
        hash.update(method.getBytes(this.charset));
        hash.update(col);
        hash.update(uri.getBytes(this.charset));
        String ha2 = bytesToHex(hash.digest());
        // compute digest
        hash.reset();
        hash.update(ha1.getBytes(this.charset));
        hash.update(col);
        hash.update(nonce.getBytes(this.charset));
        hash.update(col);
        hash.update(nc.getBytes(this.charset));
        hash.update(col);
        hash.update(cnonce.getBytes(this.charset));
        hash.update(col);
        hash.update(qop.getBytes(this.charset));
        hash.update(col);
        hash.update(ha2.getBytes(this.charset));
        return bytesToHex(hash.digest());
    }

    @Override
    public String response(String username, String password, Map<String,Object> params) {
        String realm = (String)params.get("realm");
        if (realm == null || realm.isEmpty()) {
            return null;
        }
        String nonce = (String)params.get("nonce");
        if (nonce == null || nonce.isEmpty()) {
            return null;
        }
        String qop = (String)params.get("qop");
        if (qop == null || qop.isEmpty()) {
            return null;
        }
        String nc = "00000001";
        String cnonce = intToHex(rnd.nextInt());
        String digest;
        try {
            // FIXME: don't hardcode HTTP 'method'
            digest = digest(username, password, realm, nonce, "CONNECT", "/", qop, nc, cnonce);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
        return "Proxy-Authorization: Digest " +
                "username=\""+username+"\", " +
                "realm=\""+realm+"\", " +
                "nonce=\""+nonce+"\", " +
                "uri=\""+"/"+"\", " +
                "qop=\""+qop+"\", " +
                "nc="+nc+", " +
                "cnonce=\""+cnonce+"\", " +
                "response=\""+digest+"\"" +
                "\r\n";
    }
}
