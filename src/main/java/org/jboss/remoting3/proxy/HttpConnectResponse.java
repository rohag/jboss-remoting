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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.xnio.channels.Channels;
import org.xnio.channels.StreamSourceChannel;

/**
 * Simple parser for HTTP CONNECT response.
 *
 * @author <a href="markus.uhr@immopac.ch">Markus Uhr</a>
 */
class HttpConnectResponse {

    private static final int VERSION_1 = 100;
    private static final int VERSION_2 = 101;
    private static final int VERSION_3 = 102;
    private static final int VERSION_4 = 103;
    private static final int VERSION_5 = 104;
    private static final int VERSION_6 = 105;
    private static final int STATUS_CODE_0 = 200;
    private static final int STATUS_CODE_1 = 201;
    private static final int STATUS_MESSAGE_0 = 300;
    private static final int STATUS_MESSAGE_1 = 301;
    private static final int STATUS_MESSAGE_2 = 302;
    private static final int HEADER_NAME_0 = 400;
    private static final int HEADER_VALUE_0 = 500;
    private static final int HEADER_VALUE_1 = 501;
    private static final int HEADER_VALUE_2 = 502;
    private static final int HEADER_TERMINAL = 600;
    private static final int CONTENT = 700;
    private static final int FINISHED = 999;

    private int state;
    private int pos;
    private ByteArrayOutputStream buf;
    private String hdr;
    private int contentLength;

    private String protocolVersion;
    private int responseCode;
    private String responseMessage;
    private Map<String,String> headers;
    private byte[] content;

    private HttpConnectResponse() {
        this.state = VERSION_1;
        this.pos = 0;
        this.buf = new ByteArrayOutputStream();
        this.hdr = null;
        this.contentLength = 0;
        this.headers = new HashMap<>();
        this.content = null;
    }

    public boolean isFinished() {
        return this.state == FINISHED;
    }

    public String getProtocolVersion() {
        if (this.state != FINISHED) {
            throw new IllegalStateException("Parsing is not finished.");
        }
        return this.protocolVersion;
    }

    public int getResponseCode() {
        if (this.state != FINISHED) {
            throw new IllegalStateException("Parsing is not finished.");
        }
        return this.responseCode;
    }

    public String getResponseMessage() {
        if (this.state != FINISHED) {
            throw new IllegalStateException("Parsing is not finished.");
        }
        return this.responseMessage;
    }

    public Map<String,String> getHeaders() {
        if (this.state != FINISHED) {
            throw new IllegalStateException("Parsing is not finished.");
        }
        return Collections.unmodifiableMap(this.headers);
    }

    public byte[] getContent() {
        if (this.state != FINISHED) {
            throw new IllegalStateException("Parsing is not finished.");
        }
        return this.content;
    }

    private void parse(ByteBuffer buffer) throws IOException {
        if (this.state == FINISHED) {
            throw new IllegalStateException("Parser is in FINISHED state.");
        }
        while (this.state != FINISHED && buffer.hasRemaining()) {
            byte cur = buffer.get();
            switch (this.state) {
                case VERSION_1:
                    if (cur != 'H') {
                        throw new IOException(String.format("Unexpected byte at position %d: expected 'H', found '%c'.", this.pos, cur));
                    }
                    this.state = VERSION_2;
                    break;
                case VERSION_2:
                    if (cur != 'T') {
                        throw new IOException(String.format("Unexpected byte at position %d: expected 'T', found '%c'.", this.pos, cur));
                    }
                    this.state = VERSION_3;
                    break;
                case VERSION_3:
                    if (cur != 'T') {
                        throw new IOException(String.format("Unexpected byte at position %d: expected 'T', found '%c'.", this.pos, cur));
                    }
                    this.state = VERSION_4;
                    break;
                case VERSION_4:
                    if (cur != 'P') {
                        throw new IOException(String.format("Unexpected byte at position %d: expected 'P', found '%c'.", this.pos, cur));
                    }
                    this.state = VERSION_5;
                    break;
                case VERSION_5:
                    if (cur != '/') {
                        throw new IOException(String.format("Unexpected byte at position %d: expected '/', found '%c'.", this.pos, cur));
                    }
                    this.state = VERSION_6;
                    break;
                case VERSION_6:
                    if (cur == '\r' || cur == '\n') {
                        throw new IOException(String.format("Unexpected EOL byte at position %d.", this.pos));
                    }
                    if (cur != ' ' && cur != '\t') {
                        this.buf.write(cur);
                    }
                    else {
                        this.protocolVersion = new String(this.buf.toByteArray(), StandardCharsets.UTF_8);
                        this.buf.reset();
                        this.state = STATUS_CODE_0;
                    }
                    break;
                case STATUS_CODE_0:
                    if (cur == '\r' || cur == '\n') {
                        throw new IOException(String.format("Unexpected EOL byte at position %d.", this.pos));
                    }
                    if (cur != ' ' && cur != '\t') {
                        this.buf.write(cur);
                        this.state = STATUS_CODE_1;
                    }
                    break;
                case STATUS_CODE_1:
                    if (cur == '\r' || cur == '\n') {
                        throw new IOException(String.format("Unexpected EOL byte at position %d.", this.pos));
                    }
                    if (cur != ' ' && cur != '\t') {
                        this.buf.write(cur);
                    }
                    else {
                        this.responseCode = Integer.parseInt(new String(this.buf.toByteArray(), StandardCharsets.UTF_8));
                        this.buf.reset();
                        this.state = STATUS_MESSAGE_0;
                    }
                    break;
                case STATUS_MESSAGE_0:
                    if (cur == '\n') {
                        throw new IOException(String.format("Unexpected EOL byte at position %d.", this.pos));
                    }
                    if (cur == '\r') {
                        this.responseMessage = "";
                        this.state = STATUS_MESSAGE_2;
                        break;
                    }
                    if (cur != ' ' && cur != '\t') {
                        this.buf.write(cur);
                        this.state = STATUS_MESSAGE_1;
                    }
                    break;
                case STATUS_MESSAGE_1:
                    if (cur == '\n') {
                        throw new IOException(String.format("Unexpected EOL byte at position %d.", this.pos));
                    }
                    if (cur == '\r') {
                        this.responseMessage = new String(this.buf.toByteArray(), StandardCharsets.UTF_8);
                        this.buf.reset();
                        this.state = STATUS_MESSAGE_2;
                        break;
                    }
                    this.buf.write(cur);
                    break;
                case STATUS_MESSAGE_2:
                    if (cur != '\n') {
                        throw new IOException(String.format("Unexpected byte at position %d: expected '\\n', found '%c'.", this.pos, cur));
                    }
                    this.state = HEADER_NAME_0;
                    break;
                case HEADER_NAME_0:
                    if (cur == '\n') {
                        throw new IOException(String.format("Unexpected EOL byte at position %d.", this.pos));
                    }
                    if (cur == '\r') {
                        this.state = HEADER_TERMINAL;
                        break;
                    }
                    if (cur != ':') {
                        this.buf.write(cur);
                    } else {
                        this.hdr = new String(this.buf.toByteArray(), StandardCharsets.UTF_8).toLowerCase();
                        this.buf.reset();
                        this.state = HEADER_VALUE_0;
                    }
                    break;
                case HEADER_VALUE_0:
                    if (cur == '\n') {
                        throw new IOException(String.format("Unexpected EOL byte at position %d.", this.pos));
                    }
                    if (cur == '\r') {
                        this.headers.put(this.hdr, "");
                        this.state = HEADER_VALUE_2;
                        break;
                    }
                    if (cur != ' ' && cur != '\t') {
                        this.buf.write(cur);
                        this.state = HEADER_VALUE_1;
                    }
                    break;
                case HEADER_VALUE_1:
                    if (cur == '\n') {
                        throw new IOException(String.format("Unexpected EOL byte at position %d.", this.pos));
                    }
                    if (cur == '\r') {
                        String val = new String(this.buf.toByteArray(), StandardCharsets.UTF_8);
                        this.headers.put(this.hdr, val);
                        if (this.hdr.equals("content-length")) {
                            this.contentLength = Integer.parseInt(val);
                        }
                        this.buf.reset();
                        this.state = HEADER_VALUE_2;
                        break;
                    }
                    this.buf.write(cur);
                    break;
                case HEADER_VALUE_2:
                    if (cur != '\n') {
                        throw new IOException(String.format("Unexpected byte at position %d: expected '\\n', found '%c'.", this.pos, cur));
                    }
                    this.hdr = null;
                    this.state = HEADER_NAME_0;
                    break;
                case HEADER_TERMINAL:
                    if (cur != '\n') {
                        throw new IOException(String.format("Unexpected byte at position %d: expected '\\n', found '%c'.", this.pos, cur));
                    }
                    this.state = this.contentLength > 0 ? CONTENT : FINISHED;
                    break;
                case CONTENT:
                    if (this.contentLength <= 0) {
                        throw new IllegalStateException(String.format("Invalid parser state: remaining content length = %d.", this.contentLength));
                    }
                    this.buf.write(cur);
                    this.contentLength--;
                    if (this.contentLength == 0) {
                        this.content = this.buf.toByteArray();
                        this.buf.reset();
                        this.state = FINISHED;
                    }
                    break;
                default:
                    throw new IllegalStateException(String.format("Invalid parser state: %d.", this.state));
            }
            this.pos++;
        }
    }

    public static HttpConnectResponse parse(StreamSourceChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(128);
        HttpConnectResponse result = new HttpConnectResponse();
        while (!result.isFinished()) {
            if (Channels.readBlocking(channel, buffer) == -1) {
                throw new IOException("Failed to receive HTTP response.");
            }
            buffer.flip();
            result.parse(buffer);
            buffer.clear();
        }
        return result;
    }
}
