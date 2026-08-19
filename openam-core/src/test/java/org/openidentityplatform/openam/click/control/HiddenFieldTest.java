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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.codec.binary.Base64;
import org.openidentityplatform.openam.click.util.ClickUtils;
import org.testng.annotations.Test;

/**
 * GHSA-7j4m-m698-57hp: {@code HiddenField} used to hand the value of a request parameter to
 * {@code ClickUtils.decode()} - Base64, then GZIP, then {@code ObjectInputStream.readObject()}
 * with no filter - whenever the field's value class was a {@code Serializable} other than the
 * handful it parses explicitly. No page in the product bound such a field, so the branch and the
 * encode/decode pair behind it were removed rather than filtered.
 */
public class HiddenFieldTest {

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
        try {
            field.bindRequestValue();
        } catch (IllegalArgumentException expected) {
            // The submission now takes the same path as any other value class the control does
            // not parse: it is refused, because a String is not of the declared value class.
        }

        assertFalse(Canary.deserialized,
                "the submitted serialization stream must not be deserialized");
        assertFalse(field.getValueObject() instanceof Canary,
                "no object should have been reconstructed from the parameter");
    }

    /** The same submission, on a field declared to hold an interface type. */
    @Test
    public void anInterfaceValueClassIsNoLongerDeserializedEither() throws Exception {

        Canary.deserialized = false;
        String payload = legacyEncoding(new Canary());

        SubmittedHiddenField field = new SubmittedHiddenField("canary", Serializable.class, payload);
        try {
            field.bindRequestValue();
        } catch (IllegalArgumentException expected) {
            // as above
        }

        assertFalse(Canary.deserialized,
                "the submitted serialization stream must not be deserialized");
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

    /** Reproduces exactly what the removed {@code ClickUtils.encode(Object)} produced. */
    private static String legacyEncoding(Serializable object) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream objects = new ObjectOutputStream(new GZIPOutputStream(bytes))) {
            objects.writeObject(object);
        }
        return new String(new Base64().encode(bytes.toByteArray()));
    }
}
