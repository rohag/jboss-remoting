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

import java.util.Map;

/**
 * Interface for algorithms computing proxy auth response of HTTP authorization schemes.
 *
 * @author <a href="markus.uhr@immopac.ch">Markus Uhr</a>
 */
public interface ProxyAuthResponse {
    String response(String username, String password, Map<String,Object> params);
}
