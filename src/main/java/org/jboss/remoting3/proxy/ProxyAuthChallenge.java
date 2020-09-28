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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.jboss.logging.Logger;

/**
 * Simple parser for proxy-auth challenge strings.
 *
 * @author <a href="markus.uhr@immopac.ch">Markus Uhr</a>
 */
public class ProxyAuthChallenge {

    private static final Logger log = Logger.getLogger("org.xnio.http");

    private final String scheme;

    private final Map<String,Object> params;

//    private Map<String,Map<String,String>> challenges;

    private ProxyAuthChallenge(String scheme, Map<String,Object> params) {
        this.scheme = scheme;
        this.params = params == null ? Collections.emptyMap() : Collections.unmodifiableMap(params);
//        this.challenges = new HashMap<>();
    }

//    public boolean hasScheme(String query) {
//        return this.challenges.containsKey(query.toLowerCase());
//    }

    public String getScheme() {
        return this.scheme;
    }

//    public Collection<String> getSchemes() {
//        return this.challenges.keySet();
//    }

    public Map<String,Object> getParams() {
        return this.params;
    }

//    public Map<String,String> getChallengeParams(String scheme) {
//        Map<String,String> c = this.challenges.get(scheme.toLowerCase());
//        if (c != null) {
//            c = Collections.unmodifiableMap(c);
//        }
//        return c;
//    }

    //
    // parser
    //

    // common states
    private static final int SCHEME_0 = 100;
    private static final int SCHEME_1 = 101;
    private static final int SCHEME_2 = 102;
    // HTTP states (basic, digest)
    private static final int HTTP_ARG_NAME_0 = 200;
    private static final int HTTP_ARG_NAME_1 = 201;
    private static final int HTTP_ARG_VALUE_0 = 300;
    private static final int HTTP_ARG_VALUE_1 = 301;
    private static final int HTTP_ARG_VALUE_2 = 302;
    // NTLM states
    private static final int NTLM_BLOB_0 = 600;
    private static final int NTLM_BLOB_1 = 601;
    private static final int NTLM_BLOB_2 = 602;

    private static final Base64.Decoder decoder = Base64.getDecoder();

    private static Map<String,Object> parseHttpArgs(CharSequence buffer) throws IOException {
        Map<String,Object> args = new HashMap<>();
        StringBuilder sb = new StringBuilder();
        String argName = null;
        boolean quoted = false;
        int state = HTTP_ARG_NAME_0;
        int pos = 0;
        while (pos < buffer.length()) {
            char cur = buffer.charAt(pos);
            switch (state) {
                case HTTP_ARG_NAME_0:
                    if (cur != ' ' && cur != '\t') {
                        sb.append(cur);
                        state = HTTP_ARG_NAME_1;
                    }
                    break;
                case HTTP_ARG_NAME_1:
                    if (cur == '=') {
                        argName = sb.toString().toLowerCase();
                        sb.setLength(0);
                        state = HTTP_ARG_VALUE_0;
                    }
                    else {
                        sb.append(cur);
                    }
                    break;
                case HTTP_ARG_VALUE_0:
                    if (cur == '"') {
                        state = HTTP_ARG_VALUE_1;
                        quoted = true;
                    }
                    else if (cur != ' ' && cur != '\t') {
                        sb.append(cur);
                        state = HTTP_ARG_VALUE_1;
                        quoted = false;
                    }
                    break;
                case HTTP_ARG_VALUE_1:
                    if ((quoted && cur == '"') || (!quoted && (cur == ' ' || cur == '\t'))) {
                        args.put(argName, sb.toString());
                        sb.setLength(0);
                        state = HTTP_ARG_VALUE_2;
                    }
                    else {
                        sb.append(cur);
                        if (pos == buffer.length()-1) {
                            args.put(argName, sb.toString());
                            sb.setLength(0);
                            state = HTTP_ARG_VALUE_2;
                        }
                    }
                    break;
                case HTTP_ARG_VALUE_2:
                    if (cur == ',') {
                        // FIXME: next state could also be SCHEME_0
                        state = HTTP_ARG_NAME_0;
                    }
//                    else if (pos == buffer.length()-1) {
//                        this.challenges.put(scheme, args);
//                    }
                    break;
                default:
                    throw new IllegalStateException(String.format("Invalid parser state: %d.", state));
            }
            pos++;
        }
        if (state != HTTP_ARG_VALUE_2) {
            throw  new IOException("Unexpected end of string.");
        }
        return args;
    }

    private static int readShortLE(InputStream data) throws IOException {
        int result = 0;
        int b;
        if ((b = data.read()) == -1) {
            throw new IOException("Unexpected end of stream.");
        }
        result |= b;
        if ((b = data.read()) == -1) {
            throw new IOException("Unexpected end of stream.");
        }
        result |= b << 8;
        return result;
    }

    private static int readIntLE(InputStream data) throws IOException {
        int result = 0;
        int b;
        if ((b = data.read()) == -1) {
            throw new IOException("Unexpected end of stream.");
        }
        result |= b;
        if ((b = data.read()) == -1) {
            throw new IOException("Unexpected end of stream.");
        }
        result |= b << 8;
        if ((b = data.read()) == -1) {
            throw new IOException("Unexpected end of stream.");
        }
        result |= b << 16;
        if ((b = data.read()) == -1) {
            throw new IOException("Unexpected end of stream.");
        }
        result |= b << 24;
        return result;
    }

    private static byte[] readBytes(InputStream data, int length) throws IOException {
        byte[] result = new byte[length];
        if (length == 0) {
            return result;
        }
        int offset = 0;
        do {
            int l = data.read(result, offset, length);
            if (l == -1) {
                throw new IOException("Unexpected end of stream.");
            }
            offset += l;
            length -= l;
        } while (length > 0);
        return  result;
    }

    private static String readString(InputStream data, int length, Charset charset) throws IOException {
        if (length == 0) {
            return "";
        }
        else {
            return new String(readBytes(data, length), charset);
        }
    }

    private static void skip(InputStream data, int length) throws IOException {
        while (length > 0) {
            long l = data.skip(length);
            // FIXME: detect failure condition
            length -= l;
        }
    }

    private static class NtlmBufferInfo {
        public final int length;
        public final int size;
        public final int offset;
        private NtlmBufferInfo(int l, int s, int o) {
            this.length = l;
            this.size = s;
            this.offset = o;
        }
        public static NtlmBufferInfo read(InputStream data) throws IOException {
            int length = readShortLE(data);
            int size = readShortLE(data);
            int offset = readIntLE(data);
            return new NtlmBufferInfo(length, size, offset);
        }
    }

    private static class NtlmOSVersion {
        public final int major;
        public final int minor;
        public final int build;
        private final int unknown;
        public NtlmOSVersion(int major, int minor, int build, int unknown) {
            this.major = major;
            this.minor = minor;
            this.build = build;
            this.unknown = unknown;
        }
    }

    private static Map<String,Object> readNtlmData(InputStream data) throws IOException {
        Map<String,Object> args = new HashMap<>();
        int nbuffers = 0;
        int pos = 0;
        int cur;
        // match NTLM header
        if ((cur = data.read()) != 0x4e) throw new IOException(String.format("Unexpected byte at position %d: expected 'N', found '%c'.", 0, cur));
        if ((cur = data.read()) != 0x54) throw new IOException(String.format("Unexpected byte at position %d: expected 'T', found '%c'.", 1, cur));
        if ((cur = data.read()) != 0x4c) throw new IOException(String.format("Unexpected byte at position %d: expected 'L', found '%c'.", 2, cur));
        if ((cur = data.read()) != 0x4d) throw new IOException(String.format("Unexpected byte at position %d: expected 'M', found '%c'.", 3, cur));
        if ((cur = data.read()) != 0x53) throw new IOException(String.format("Unexpected byte at position %d: expected 'S', found '%c'.", 4, cur));
        if ((cur = data.read()) != 0x53) throw new IOException(String.format("Unexpected byte at position %d: expected 'S', found '%c'.", 5, cur));
        if ((cur = data.read()) != 0x50) throw new IOException(String.format("Unexpected byte at position %d: expected 'P', found '%c'.", 6, cur));
        if ((cur = data.read()) != 0x00) throw new IOException(String.format("Unexpected byte at position %d: expected '\\0', found '%c'.", 7, cur));
        pos += 8;
        // match message type
        if ((cur = data.read()) != 0x02) throw new IOException(String.format("Unexpected byte at position %d: expected 0x02, found 0x%x.",  8, cur));
        if ((cur = data.read()) != 0x00) throw new IOException(String.format("Unexpected byte at position %d: expected 0x00, found 0x%x.",  9, cur));
        if ((cur = data.read()) != 0x00) throw new IOException(String.format("Unexpected byte at position %d: expected 0x00, found 0x%x.", 10, cur));
        if ((cur = data.read()) != 0x00) throw new IOException(String.format("Unexpected byte at position %d: expected 0x00, found 0x%x.", 11, cur));
        pos += 4;
        // target name
        NtlmBufferInfo targetName = NtlmBufferInfo.read(data);
        if (targetName.length > 0 && targetName.size > 0) {
            nbuffers++;
        }
        pos += 8;
        // read flags
        int flags = readIntLE(data);
        args.put("flags", flags);
        pos += 4;
        // read challenge
        args.put("challenge", readBytes(data, 8));
        pos += 8;
        // read context
        args.put("context", readBytes(data, 8));
        pos += 8;
        // target info
        NtlmBufferInfo targetInfo = NtlmBufferInfo.read(data);
        if (targetInfo.length > 0 && targetInfo.size > 0) {
            nbuffers++;
        }
        pos += 8;
        // OS version info
        NtlmOSVersion os = null;
        if (targetName.offset > 48) {
            int major = data.read();
            int minor = data.read();
            int build = readShortLE(data);
            int unknown = readIntLE(data);
            os = new NtlmOSVersion(major, minor, build, unknown);
            pos += 8;
        }
        Charset charset = (flags & 0x03) == 1 ? StandardCharsets.UTF_16LE : StandardCharsets.US_ASCII;
        // read buffers
        while (nbuffers > 0) {
            if (pos == targetName.offset) {
                // read target name
                args.put("targetName", readString(data, targetName.length, charset));
                skip(data, targetName.size - targetName.length);
                pos += targetName.size;
            }
            else if (pos == targetInfo.offset) {
                // read target info
                do {
                    int type = readShortLE(data);
                    int length = readShortLE(data);
                    if (type == 0 && length == 0) {
                        break; // end of list marker
                    }
                    String key = null;
                    Object val = null;
                    switch (type) {
                        case 1:
                            key = "serverName"; // NetBIOS computer name
                            val = readString(data, length, StandardCharsets.UTF_16LE);
                            break;
                        case 2:
                            key = "domainName"; // NetBIOS domain name
                            val = readString(data, length, StandardCharsets.UTF_16LE);
                            break;
                        case 3:
                            key = "dnsServerName"; // computer's fully qualified domain name
                            val = readString(data, length, StandardCharsets.UTF_16LE);
                            break;
                        case 4:
                            key = "dnsDomainName"; // domain's fully qualified domain name
                            val = readString(data, length, StandardCharsets.UTF_16LE);
                            break;
                        case 5:
                            key = "dnsTreeName"; // forest's fully qualified domain name
                            val = readString(data, length, StandardCharsets.UTF_16LE);
                            break;
                        case 6:
                            key = "targetFlags"; // additional flags
                            val = readIntLE(data);
                            break;
                        case 7:
                            key = "timestamp"; // server local time
                            val = readBytes(data, length);
                            break;
                        case 8:
                            key = "singleHost"; // 'Single Host Data' structure
                            val = readBytes(data, length);
                            break;
                        case 9:
                            key = "spnTargetName"; // SPN of the target server
                            val = readBytes(data, length);
                            break;
                        case 10:
                            key = "channelBindings"; // channel bindings hash
                            val = readBytes(data, length);
                            break;
                        default:
                            if (log.isDebugEnabled()) {
                                log.debugf("Ignoring unsupported target info type %d.", type);
                            }
                            skip(data, length);
                            break;
                    }
                    if (key != null) {
                        args.put(key, val);
                    }
                } while (true);
                skip(data, targetInfo.size - targetInfo.length);
                pos += targetInfo.size;
            }
            else {
                throw new IOException("Invalid stream offset.");
            }
            // next buffer
            nbuffers--;
        }
        return args;
    }

    private static Map<String,Object> parseNtlmArgs(CharSequence buffer) throws IOException {
        StringBuilder sb = new StringBuilder();
        int state = NTLM_BLOB_0;
        int pos = 0;
        while (state != NTLM_BLOB_2 && pos < buffer.length()) {
            char cur = buffer.charAt(pos);
            switch (state) {
                case NTLM_BLOB_0:
                    if (cur != ' ' && cur != '\t') {
                        sb.append(cur);
                        state = NTLM_BLOB_1;
                    }
                    else if (pos == buffer.length()-1) {
                        state = NTLM_BLOB_2;
                    }
                    break;
                case NTLM_BLOB_1:
                    if (cur != ' ' && cur != '\t') {
                        sb.append(cur);
                        if (pos == buffer.length()-1) {
                            state = NTLM_BLOB_2;
                        }
                    }
                    else {
                        state = NTLM_BLOB_2;
                    }
                    break;
                default:
                    throw new IllegalStateException(String.format("Invalid parser state: %d.", state));
            }
            pos++;
        }
        if (state != NTLM_BLOB_2) {
            throw  new IOException("Unexpected end of string.");
        }
        return readNtlmData(new ByteArrayInputStream(decoder.decode(sb.toString())));
    }

    public static ProxyAuthChallenge parse(CharSequence buffer) throws IOException {
        if (buffer == null || buffer.length() == 0) {
            return null;
        }
        int state = SCHEME_0;
        int pos = 0;
        StringBuilder sb = new StringBuilder();
        String scheme = null;
        while (state != SCHEME_2 && pos < buffer.length()) {
            char cur = buffer.charAt(pos);
            switch (state) {
                case SCHEME_0:
                    if (cur != ' ' && cur != '\t') {
                        sb.append(cur);
                        state = SCHEME_1;
                    }
                    break;
                case SCHEME_1:
                    if (cur != ' ' && cur != '\t') {
                        sb.append(cur);
                        if (pos == buffer.length()-1) {
                            scheme = sb.toString().toLowerCase();
                            state = SCHEME_2;
                        }
                    }
                    else {
                        scheme = sb.toString().toLowerCase();
                        state = SCHEME_2;
                    }
                    break;
                default:
                    throw new IllegalStateException(String.format("Invalid parser state: %d.", state));
            }
            pos++;
        }
        if (state != SCHEME_2) {
            throw  new IOException("Unexpected end of string.");
        }
        Map<String,Object> args = null;
        switch (scheme) {
            case "basic":
            case "digest":
                args = parseHttpArgs(buffer.subSequence(pos, buffer.length()));
                break;
            case "ntlm":
                if (pos < buffer.length()) {
                    args = parseNtlmArgs(buffer.subSequence(pos, buffer.length()));
                }
                break;
            default:
                log.debugf("Unsupported proxy scheme: '%s'.", scheme);
                break;
        }
        return new ProxyAuthChallenge(scheme, args);
    }
}
