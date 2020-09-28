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
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.jboss.logging.Logger;
import org.xnio.FutureResult;
import org.xnio.IoUtils;
import org.xnio.OptionMap;
import org.xnio.StreamConnection;
import org.xnio.channels.Channels;
import org.xnio.channels.StreamSinkChannel;

/**
 * Simple HTTP client to request an SSL/TLS tunnel (<a href="https://www.ietf.org/rfc/rfc2817.txt">RFC 2817</a>).
 *
 * @author <a href="mailto:markus.uhr@immopac.ch">Markus Uhr</a>
 */
public class HttpConnect {

    private static final Logger log = Logger.getLogger("org.xnio.http");

    private static class HttpConnectState {

        private final InetSocketAddress dest;
        private final Map<String,List<String>> headers;
        private final OptionMap optionMap;

        private final FutureResult<? extends StreamConnection> future;

        HttpConnectState(InetSocketAddress dest, Map<String,List<String>> headers, OptionMap optionMap, FutureResult<? extends StreamConnection> future) {
            this.dest = dest;
            this.headers = headers;
            this.optionMap = optionMap;
            this.future = future;
        }

        private void sendHttpRequest(StreamSinkChannel channel, ProxyAuthResponse par, Map<String,Object> params) throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream(1024);
            OutputStreamWriter sw = new OutputStreamWriter(buf);
            sw.append("CONNECT ");
            sw.append(dest.getHostString());
            sw.append(":");
            sw.append(dest.getPort() >= 0 ? Integer.toString(dest.getPort()) : "443");
            sw.append(" HTTP/1.1\r\n");
            boolean host = false;
            String authResponse = null;
            for (Map.Entry<String,List<String>> headerEntry : headers.entrySet()) {
                for(String value : headerEntry.getValue()) {
                    sw.append(headerEntry.getKey());
                    sw.append(": ");
                    sw.append(value);
                    sw.append("\r\n");
                    String hkey = headerEntry.getKey().toLowerCase(Locale.ENGLISH);
                    host = hkey.equals("host");
                }
            }
            if (!host) {
                sw.append("Host: ");
                sw.append(dest.getHostString());
                sw.append(":");
                sw.append(dest.getPort() >= 0 ? Integer.toString(dest.getPort()) : "443");
                sw.append("\r\n");
            }
            if (par != null) {
                String username = System.getProperty("http.proxyAuthUsername");
                String password = System.getProperty("http.proxyAuthPassword");
                authResponse = par.response(username, password, params);
                sw.append(authResponse);
            }
            sw.append("\r\n");
            sw.flush();
            ByteBuffer buffer = ByteBuffer.wrap(buf.toByteArray());
            if (log.isDebugEnabled()) {
                log.debugf("Sending HTTP CONNECT...");
                if (authResponse != null && !authResponse.isEmpty()) {
                    log.tracef("    %s", authResponse.substring(0, authResponse.length()-2));
                }
            }
            Channels.writeBlocking(channel, buffer);
        }

        private void doConnect(StreamConnection connection) {
            try {
                final int MAX_TRIES = 3;
                int numTries = 0;
                HttpConnectResponse response = null;
                // send authorization header for schemes 'basic' and 'ntlm' eagerly
                String scheme = System.getProperty("http.proxyAuthScheme");
                ProxyAuthChallenge pac = null;
                ProxyAuthResponse par = null;
                if (scheme != null && !scheme.isEmpty()) {
                    switch (scheme.toLowerCase()) {
                        case "basic":
                            par = new BasicProxyAuthResponse();
                            break;
//                        case "digest":
//                            par = new DigestProxyAuthResponse();
//                            break;
                        case "ntlm":
                            String domain = System.getProperty("http.proxyAuthNtlmDomain");
                            String workstation = System.getProperty("http.proxyAuthNtlmWorkstation");
                            par = new NtlmProxyAuthResponse(domain, workstation);
                            break;
                    }
                }
                do {
                    sendHttpRequest(connection.getSinkChannel(), par, pac != null ? pac.getParams() : null);
                    response = HttpConnectResponse.parse(connection.getSourceChannel());
                    if (log.isTraceEnabled()) {
                        log.tracef("Server response: %d %s", response.getResponseCode(), response.getResponseMessage());
                        for (Map.Entry<String, String> hdr : response.getHeaders().entrySet()) {
                            log.tracef("    %s: %s", hdr.getKey(), hdr.getValue());
                        }
                        if (response.getContent() != null) {
                            log.tracef("Message Content: skipping %s bytes.", response.getHeaders().get("content-length"));
                        }
                    }
                    if (response.getResponseCode() == 407) {
                        String challenge = response.getHeaders().get("proxy-authenticate");
                        pac = ProxyAuthChallenge.parse(challenge);
                        par = null;
                        if (pac != null) {
                            if (pac.getScheme().compareToIgnoreCase("Digest") == 0) {
                                par = new DigestProxyAuthResponse();
                            } else if (pac.getScheme().compareToIgnoreCase("NTLM") == 0) {
                                String domain = System.getProperty("http.proxyAuthNtlmDomain");
                                String workstation = System.getProperty("http.proxyAuthNtlmWorkstation");
                                par = new NtlmProxyAuthResponse(domain, workstation);
                            } else if (pac.getScheme().compareToIgnoreCase("Basic") == 0) {
                                par = new BasicProxyAuthResponse();
                            }
                        }
                    }
                    numTries++;
                } while (response.getResponseCode() == 407 && numTries < MAX_TRIES);
                if (response.getResponseCode() == 407) {
                    IoUtils.safeClose(connection);
                    this.future.setException(new ConnectFailedException("Failed to authenticate with proxy."));
                }
                if (response.getResponseCode() < 200 || response.getResponseCode() >= 300) {
                    IoUtils.safeClose(connection);
                    this.future.setException(new ConnectFailedException(String.format("Invalid response code %d.", response.getResponseCode())));
                }
            } catch (IOException ex) {
                IoUtils.safeClose(connection);
                this.future.setException(ex);
            }
        }
    }

    public static <T extends StreamConnection> void performConnect(T connection, InetSocketAddress dest, OptionMap optionMap, FutureResult<? extends StreamConnection> future) {
        new HttpConnectState(dest, Collections.emptyMap(), optionMap, future).doConnect(connection);
    }
}
