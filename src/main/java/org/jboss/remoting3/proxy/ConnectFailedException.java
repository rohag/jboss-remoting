/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2014 Red Hat, Inc. and/or its affiliates.
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

import java.io.IOException;

/**
 * Exception that is thrown when the response to an HTTP request is
 * not a 2xx code.
 *
 * @author <a href="markus.uhr@immopac.ch">Markus Uhr</a>
 */
public class ConnectFailedException extends IOException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@code ConnectFailedException} instance.  The message is left blank ({@code null}), and no cause
     * is specified.
     */
    public ConnectFailedException() {
    }

    /**
     * Constructs a new {@code ConnectFailedException} instance with an initial message.  No cause is specified.
     *
     * @param msg the message
     */
    public ConnectFailedException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code ConnectFailedException} instance with an initial cause.  If a non-{@code null} cause is
     * specified, its message is used to initialize the message of this {@code ConnectFailedException}; otherwise the
     * message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public ConnectFailedException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code ConnectFailedException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     */
    public ConnectFailedException(final String msg, final Throwable cause) {
        super(msg, cause);
    }
}
