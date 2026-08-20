/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 3A Systems, LLC.
 */

package org.openidentityplatform.openam.click.control;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.Date;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.codec.binary.Base64;
import org.openidentityplatform.openam.click.util.ClickUtils;
import org.openidentityplatform.openam.click.util.HtmlStringBuffer;
import org.testng.annotations.Test;

/**
 * GHSA-7j4m-m698-57hp: {@code HiddenField} used to hand the value of a request parameter to
 * {@code ClickUtils.decode()} - Base64, then GZIP, then {@code ObjectInputStream.readObject()}
 * with no filter - whenever the field's value class was a {@code Serializable} other than the
 * handful it parses explicitly. No page in the product bound such a field, so the branch and the
 * encode/decode pair behind it were removed rather than filtered.
 */
public class HiddenFieldTest {

    /** A payload that must never reach the rendered markup unescaped. */
    private static final String XSS = "\"><script>alert(1)</script>";

    /** The same payload as {@code HtmlStringBuffer.appendAttributeEscaped()} writes it. */
    private static final String XSS_ESCAPED =
            "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;";

    /**
     * Records whether Java deserialization ran. A gadget would use this moment to do something
     * less polite.
     */
    public static class Canary implements Serializable {

        private static final long serialVersionUID = 1L;

        static volatile boolean deserialized = false;

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            deserialized = true;
        }
    }

    /**
     * A Serializable value class the control does not parse. Its rendering used to be intercepted
     * by the removed {@code instanceof Serializable} arm, which wrote
     * {@code ClickUtils.encode(...)} through the unescaped {@code appendAttribute}; it now falls
     * to the escaping branch at the end of {@link HiddenField#render(HtmlStringBuffer)}.
     */
    public static class Unsupported implements Serializable {

        private static final long serialVersionUID = 1L;

        @Override
        public String toString() {
            return XSS;
        }
    }

    /** A field whose request value is supplied directly, so no Click Context is needed. */
    private static final class SubmittedHiddenField extends HiddenField {

        private final String requestValue;

        SubmittedHiddenField(String name, Class<?> valueClass, String requestValue) {
            super(name, valueClass);
            this.requestValue = requestValue;
        }

        @Override
        protected String getRequestValue() {
            return requestValue;
        }
    }

    @Test
    public void aSerializableValueClassIsNoLongerDeserialized() throws Exception {

        Canary.deserialized = false;
        String payload = legacyEncoding(new Canary());

        SubmittedHiddenField field = new SubmittedHiddenField("canary", Canary.class, payload);

        // The submission takes the same path as any other value class the control does not parse:
        // it is refused, because a String is not of the declared value class. Asserting that the
        // refusal happens keeps the canary assertion below from being satisfied by a bind that
        // never reached the branch under test.
        assertThrows(IllegalArgumentException.class, field::bindRequestValue);

        assertFalse(Canary.deserialized,
                "the submitted serialization stream must not be deserialized");
        assertNull(field.getValueObject(),
                "no object should have been reconstructed from the parameter");
    }

    /** The same submission, on a field declared to hold an interface type. */
    @Test
    public void anInterfaceValueClassIsNoLongerDeserializedEither() throws Exception {

        Canary.deserialized = false;
        String payload = legacyEncoding(new Canary());

        SubmittedHiddenField field = new SubmittedHiddenField("canary", Serializable.class, payload);

        assertThrows(IllegalArgumentException.class, field::bindRequestValue);

        assertFalse(Canary.deserialized,
                "the submitted serialization stream must not be deserialized");
        assertNull(field.getValueObject(),
                "no object should have been reconstructed from the parameter");
    }

    /** The round trip has no caller left, and no longer exists to acquire one. */
    @Test
    public void clickUtilsNoLongerCarriesTheSerializationRoundTrip() {

        for (Method method : ClickUtils.class.getDeclaredMethods()) {
            assertFalse("decode".equals(method.getName()) && method.getParameterCount() == 1
                            && method.getParameterTypes()[0] == String.class,
                    "ClickUtils.decode(String) is an unfiltered readObject() sink and must stay removed");
            assertFalse("encode".equals(method.getName()) && method.getParameterCount() == 1
                            && method.getParameterTypes()[0] == Object.class,
                    "ClickUtils.encode(Object) produced the format decode(String) read and must stay removed");
        }
    }

    /** The value classes the control actually supports still bind. */
    @Test
    public void supportedValueClassesStillBind() {

        SubmittedHiddenField text = new SubmittedHiddenField("text", String.class, "hello");
        text.bindRequestValue();
        assertEquals(text.getValueObject(), "hello");

        SubmittedHiddenField number = new SubmittedHiddenField("number", Long.class, "42");
        number.bindRequestValue();
        assertEquals(number.getValueObject(), 42L);

        SubmittedHiddenField flag = new SubmittedHiddenField("flag", Boolean.class, "true");
        flag.bindRequestValue();
        assertEquals(flag.getValueObject(), Boolean.TRUE);

        SubmittedHiddenField empty = new SubmittedHiddenField("empty", Long.class, "");
        empty.bindRequestValue();
        assertNull(empty.getValueObject(), "an empty submission binds nothing");
    }

    /**
     * The branch the removed {@code instanceof Serializable} arm used to intercept. This is the
     * one rendering path this change moved, and the escaping call it lands on is what stands
     * between a value class the control does not parse and its markup.
     */
    @Test
    public void renderEscapesAValueClassTheControlDoesNotParse() {

        HiddenField field = new HiddenField("unsupported", Unsupported.class);
        field.setValueObject(new Unsupported());

        HtmlStringBuffer buffer = new HtmlStringBuffer();
        field.render(buffer);

        assertFalse(buffer.toString().contains("<script>"),
                "the value attribute must be escaped, was: " + buffer);
        assertTrue(buffer.toString().contains("value=\"" + XSS_ESCAPED + "\""),
                "unexpected rendering: " + buffer);
    }

    /** The same guarantee for String, the only value class a shipped page could reach. */
    @Test
    public void renderEscapesAStringValue() {

        HiddenField text = new HiddenField("text", String.class);
        text.setValue(XSS);

        HtmlStringBuffer buffer = new HtmlStringBuffer();
        text.render(buffer);

        assertFalse(buffer.toString().contains("<script>"),
                "the value attribute must be escaped, was: " + buffer);
        assertTrue(buffer.toString().contains("value=\"" + XSS_ESCAPED + "\""),
                "unexpected rendering: " + buffer);
    }

    /** The remaining rendering branches still write what they always wrote. */
    @Test
    public void renderWritesNumbersAndDatesUnchanged() {

        HiddenField number = new HiddenField("number", Long.class);
        number.setValueObject(42L);

        HtmlStringBuffer numberBuffer = new HtmlStringBuffer();
        number.render(numberBuffer);
        assertTrue(numberBuffer.toString().contains("value=\"42\""),
                "unexpected rendering: " + numberBuffer);

        HiddenField date = new HiddenField("date", Date.class);
        date.setValueObject(new Date(1234567890000L));

        HtmlStringBuffer dateBuffer = new HtmlStringBuffer();
        date.render(dateBuffer);
        assertTrue(dateBuffer.toString().contains("value=\"1234567890000\""),
                "unexpected rendering: " + dateBuffer);
    }

    /** Reproduces exactly what the removed {@code ClickUtils.encode(Object)} produced. */
    private static String legacyEncoding(Serializable object) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream objects = new ObjectOutputStream(new GZIPOutputStream(bytes))) {
            objects.writeObject(object);
        }
        return new String(new Base64().encode(bytes.toByteArray()));
    }
}
