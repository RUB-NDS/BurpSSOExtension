/**
 * EsPReSSO - Extension for Processing and Recognition of Single Sign-On Protocols.
 * Copyright (C) 2015 Tim Guenther and Christian Mainka
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package de.rub.nds.burp.utilities;

/**
 *
 */
public class ByteArrayHelper {
    
    /**
     * Converts a string with an even number of hexadecimal characters to a byte
     * array.
     *
     * @param input
     *            hex string
     * @return byte array
     */
    public static byte[] hexStringToByteArray(String input) {
        input = input.replaceAll("\\s", "");
        if ((input == null) || (input.length() % 2 != 0)) {
            throw new IllegalArgumentException("The input must not be null and "
                    + "shall have an even number of hexadecimal characters. Found: " + input);
        }
        byte[] output = new byte[input.length() / 2];
        for (int i = 0; i < output.length; i++) {
            output[i] = (byte) ((Character.digit(input.charAt(i * 2), 16) << 4) + Character.digit(
                    input.charAt(i * 2 + 1), 16));
        }
        return output;
    }
    
    public static String bytesToHexString(byte[] array) {
        if (array == null) {
            array = new byte[0];
        }
        boolean usePrettyPrinting = (array.length > 15);
        return bytesToHexString(array, usePrettyPrinting);
    }

    public static String bytesToHexString(byte[] array, boolean usePrettyPrinting) {
        if (array == null) {
            array = new byte[0];
        }
        return bytesToHexString(array, usePrettyPrinting, true);
    }

    public static String bytesToHexString(byte[] array, boolean usePrettyPrinting, boolean initialNewLine) {
        StringBuilder result = new StringBuilder();
        if (initialNewLine && usePrettyPrinting) {
            result.append("\n");
        }
        for (int i = 0; i < array.length; i++) {
            if (i != 0) {
                if (usePrettyPrinting && (i % 16 == 0)) {
                    result.append("\n");
                } else {
                    if (usePrettyPrinting && (i % 8 == 0)) {
                        result.append(" ");
                    }
                    result.append(" ");
                }
            }
            byte b = array[i];
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
    
    public static byte[] concatenate(final byte[]... arrays) {
        if (arrays == null || arrays.length == 0) {
            throw new IllegalArgumentException("The minimal number of parameters for this function is one");
        }
        int length = 0;
        for (final byte[] a : arrays) {
            if (a != null) {
                length += a.length;
            }
        }
        byte[] result = new byte[length];
        int currentOffset = 0;
        for (final byte[] a : arrays) {
            if (a != null) {
                System.arraycopy(a, 0, result, currentOffset, a.length);
                currentOffset += a.length;
            }
        }
        return result;
    }
}
