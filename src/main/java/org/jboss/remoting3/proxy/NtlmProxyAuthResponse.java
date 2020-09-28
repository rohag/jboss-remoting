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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import sun.security.provider.MD4;

/**
 * Algorithm for computing proxy auth response of "NTLM" authorization scheme.
 *
 * Documentation:
 *     http://davenport.sourceforge.net/ntlm.html
 *     https://www.innovation.ch/personal/ronald/ntlm.html
 *
 * @author <a href="markus.uhr@immopac.ch">Markus Uhr</a>
 */
public class NtlmProxyAuthResponse implements ProxyAuthResponse {

    private static final Base64.Encoder encoder = Base64.getEncoder();

    private final Charset charset;

    private final String domain;
    private final String workstation;

    public NtlmProxyAuthResponse(String domain, String workstation) {
        this(StandardCharsets.UTF_8, domain, workstation);
    }

    public NtlmProxyAuthResponse(Charset charset, String domain, String workstation) {
        this.charset = charset;
        this.domain = domain;
        this.workstation = workstation;
    }

    private static void writeNtlmSignature(OutputStream buffer) throws IOException {
        buffer.write(0x4e); // 'N'
        buffer.write(0x54); // 'T'
        buffer.write(0x4c); // 'L'
        buffer.write(0x4d); // 'M'
        buffer.write(0x53); // 'S'
        buffer.write(0x53); // 'S'
        buffer.write(0x50); // 'P'
        buffer.write(0x00); // '\0'
    }

    private static void writeShortLE(OutputStream buffer, int value) throws IOException {
        buffer.write(value & 0xFF);
        value >>= 8;
        buffer.write(value & 0xFF);
    }

    private static void writeIntLE(OutputStream buffer, int value) throws IOException {
        buffer.write(value & 0xFF);
        value >>= 8;
        buffer.write(value & 0xFF);
        value >>= 8;
        buffer.write(value & 0xFF);
        value >>= 8;
        buffer.write(value & 0xFF);
    }

//    private static void writeLongLE(OutputStream buffer, long value) throws IOException {
//        buffer.write((int)(value & 0xFF));
//        value >>= 8;
//        buffer.write((int)(value & 0xFF));
//        value >>= 8;
//        buffer.write((int)(value & 0xFF));
//        value >>= 8;
//        buffer.write((int)(value & 0xFF));
//        value >>= 8;
//        buffer.write((int)(value & 0xFF));
//        value >>= 8;
//        buffer.write((int)(value & 0xFF));
//        value >>= 8;
//        buffer.write((int)(value & 0xFF));
//        value >>= 8;
//        buffer.write((int)(value & 0xFF));
//    }

    private static void writeString(OutputStream buffer, String value, Charset charset) throws IOException {
        buffer.write(value.getBytes(charset));
    }

    private static void oddParity(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            boolean needsParity = (((b >>> 7) ^ (b >>> 6) ^ (b >>> 5) ^ (b >>> 4) ^ (b >>> 3) ^ (b >>> 2) ^ (b >>> 1)) & 0x01) == 0;
            if (needsParity) {
                bytes[i] |= (byte) 0x01;
            } else {
                bytes[i] &= (byte) 0xfe;
            }
        }
    }

    private static Key createDESKey(byte[] bytes, int offset) {
        byte[] keyBytes = new byte[7];
        System.arraycopy(bytes, offset, keyBytes, 0, 7);
        byte[] material = new byte[8];
        material[0] = keyBytes[0];
        material[1] = (byte)(keyBytes[0] << 7 | (keyBytes[1] & 0xff) >>> 1);
        material[2] = (byte)(keyBytes[1] << 6 | (keyBytes[2] & 0xff) >>> 2);
        material[3] = (byte)(keyBytes[2] << 5 | (keyBytes[3] & 0xff) >>> 3);
        material[4] = (byte)(keyBytes[3] << 4 | (keyBytes[4] & 0xff) >>> 4);
        material[5] = (byte)(keyBytes[4] << 3 | (keyBytes[5] & 0xff) >>> 5);
        material[6] = (byte)(keyBytes[5] << 2 | (keyBytes[6] & 0xff) >>> 6);
        material[7] = (byte)(keyBytes[6] << 1);
        oddParity(material);
        return new SecretKeySpec(material, "DES");
    }

    private static byte[] lmHash(String password) throws GeneralSecurityException {
        byte[] oemPassword = password.toUpperCase().getBytes(StandardCharsets.US_ASCII);
        int length = Math.min(oemPassword.length, 14);
        byte[] keyBytes = new byte[14];
        System.arraycopy(oemPassword, 0, keyBytes, 0, length);
        Key lowKey = createDESKey(keyBytes, 0);
        Key highKey = createDESKey(keyBytes, 7);
        byte[] magicConstant = "KGS!@#$%".getBytes(StandardCharsets.US_ASCII);
        Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
        des.init(Cipher.ENCRYPT_MODE, lowKey);
        byte[] lowHash = des.doFinal(magicConstant);
        des.init(Cipher.ENCRYPT_MODE, highKey);
        byte[] highHash = des.doFinal(magicConstant);
        byte[] lmHash = new byte[16];
        System.arraycopy(lowHash, 0, lmHash, 0, 8);
        System.arraycopy(highHash, 0, lmHash, 8, 8);
        return lmHash;
    }

    private static byte[] ntlmHash(String password) throws GeneralSecurityException {
        byte[] unicodePassword = password.getBytes(StandardCharsets.UTF_16LE);
        MessageDigest md4 = MD4.getInstance(); //MessageDigest.getInstance("MD4");
        return md4.digest(unicodePassword);
    }

    private static byte[] lmResponse(byte[] hash, byte[] challenge) throws GeneralSecurityException {
        byte[] keyBytes = new byte[21];
        System.arraycopy(hash, 0, keyBytes, 0, 16);
        Key lowKey = createDESKey(keyBytes, 0);
        Key middleKey = createDESKey(keyBytes, 7);
        Key highKey = createDESKey(keyBytes, 14);
        Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
        des.init(Cipher.ENCRYPT_MODE, lowKey);
        byte[] lowResponse = des.doFinal(challenge);
        des.init(Cipher.ENCRYPT_MODE, middleKey);
        byte[] middleResponse = des.doFinal(challenge);
        des.init(Cipher.ENCRYPT_MODE, highKey);
        byte[] highResponse = des.doFinal(challenge);
        byte[] result = new byte[24];
        System.arraycopy(lowResponse, 0, result, 0, 8);
        System.arraycopy(middleResponse, 0, result, 8, 8);
        System.arraycopy(highResponse, 0, result, 16, 8);
        return result;
    }

    private static void writeLMResponse(OutputStream buffer, String password, byte[] challenge) throws GeneralSecurityException, IOException {
        byte[] lmHash = lmHash(password);
        buffer.write(lmResponse(lmHash, challenge));
    }

    private static void writeNTLMResponse(OutputStream buffer, String password, byte[] challenge) throws GeneralSecurityException, IOException {
        byte[] ntlmHash = ntlmHash(password);
        buffer.write(lmResponse(ntlmHash, challenge));
    }

//    private String encode(String text) {
//        return encode(text.getBytes(this.charset));
//    }

    private String encode(byte[] buffer) {
        return new String(encoder.encode(buffer), this.charset);
    }

    @Override
    public String response(String username, String password, Map<String,Object> params) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        if (params == null || params.size() == 0) {
            // type 1 message
            try {
                int bufOfs = 0x28;
                // signature
                writeNtlmSignature(buffer);
                // message type
                writeIntLE(buffer, 0x01);
                // flags
                writeIntLE(buffer, 0x3203);
                // domain security buffer
                int dlen = this.domain != null ? this.domain.length() : 0;
                writeShortLE(buffer, dlen); // length
                writeShortLE(buffer, dlen); // size
                writeIntLE(buffer, bufOfs); // offset
                bufOfs += dlen;
                // workstation security buffer
                int wlen = this.workstation != null ? this.workstation.length() : 0;
                writeShortLE(buffer, wlen); // length
                writeShortLE(buffer, wlen); // size
                writeIntLE(buffer, bufOfs); // offset
                bufOfs += wlen;
                // domain name
                if (dlen > 0) {
                    writeString(buffer, this.domain, StandardCharsets.US_ASCII);
                }
                // workstation name
                if (wlen > 0) {
                    writeString(buffer, this.workstation, StandardCharsets.US_ASCII);
                }
            } catch (IOException ex) {
                return null;
            }
        }
        else {
            // type 3 message
            try {
                int l;
                int bufOfs = 0x40;
                int flags = (int)params.get("flags");
                int charwidth = (flags & 0x03) == 1 ? 2 : 1;
                Charset charset = charwidth == 1 ? StandardCharsets.US_ASCII : StandardCharsets.UTF_16LE;
                // signature
                writeNtlmSignature(buffer);
                // message type
                writeIntLE(buffer, 0x03);
                // LM security buffer
                writeShortLE(buffer, 0x18);
                writeShortLE(buffer, 0x18);
                writeIntLE(buffer, bufOfs);
                bufOfs += 0x18;
                // NTLM security buffer
                writeShortLE(buffer, 0x18);
                writeShortLE(buffer, 0x18);
                writeIntLE(buffer, bufOfs);
                bufOfs += 0x18;
                // target (domain) name security buffer
                String dval = (String)params.getOrDefault("domainName", this.domain);
                int dlen = dval != null ? dval.length()*charwidth : 0;
                writeShortLE(buffer, dlen);
                writeShortLE(buffer, dlen);
                writeIntLE(buffer, bufOfs);
                bufOfs += dlen;
                // user name security buffer
                l = username.length()*charwidth;
                writeShortLE(buffer, l);
                writeShortLE(buffer, l);
                writeIntLE(buffer, bufOfs);
                bufOfs += l;
                // workstation security buffer
                int wlen = this.workstation != null ? this.workstation.length()*charwidth : 0;
                writeShortLE(buffer, wlen);
                writeShortLE(buffer, wlen);
                writeIntLE(buffer, bufOfs);
                bufOfs += wlen;
                // session key security buffer (always empty)
                writeShortLE(buffer, 0x00);
                writeShortLE(buffer, 0x00);
                writeIntLE(buffer, bufOfs);
                // flags
                writeIntLE(buffer, flags);
                // LM response
                writeLMResponse(buffer, password, (byte[])params.get("challenge"));
                // NTLM response
                writeNTLMResponse(buffer, password, (byte[])params.get("challenge"));
                // target (domain) name
                if (dlen > 0) {
                    writeString(buffer, dval, charset);
                }
                // user name
                writeString(buffer, username, charset);
                // workstation name
                if (wlen > 0) {
                    writeString(buffer, this.workstation, charset);
                }
            } catch (IOException|GeneralSecurityException ex) {
                return null;
            }

        }
        return String.format("Proxy-Authorization: NTLM %s\r\n",  encode(buffer.toByteArray()));
    }
}
