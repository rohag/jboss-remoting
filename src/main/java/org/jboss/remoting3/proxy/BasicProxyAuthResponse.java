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
import java.util.Base64;
import java.util.Map;

/**
 * Algorithm for computing proxy auth response of "Basic" authorization scheme.
 *
 * @author <a href="markus.uhr@immopac.ch">Markus Uhr</a>
 */
public class BasicProxyAuthResponse implements ProxyAuthResponse {

    private static final Base64.Encoder encoder = Base64.getEncoder();

    private final Charset charset;

    public BasicProxyAuthResponse() {
        this(StandardCharsets.UTF_8);
    }

    public BasicProxyAuthResponse(Charset charset) {
        this.charset = charset;
    }

    private String encode(String text) {
        return new String(encoder.encode(text.getBytes(this.charset)), this.charset);
    }

    @Override
    public String response(String username, String password, Map<String,Object> params) {
//        String realm = (String)params.get("realm");
//        if (realm == null || realm.isEmpty()) {
//            return null;
//        }
        return String.format("Proxy-Authorization: Basic %s\r\n", encode(String.format("%s:%s", username, password)));
    }
}
