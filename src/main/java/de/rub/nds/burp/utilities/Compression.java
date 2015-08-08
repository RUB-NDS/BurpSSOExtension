/**
 * EsPReSSO - Extension for Processing and Recognition of Single Sign-On Protocols.
 * Copyright (C) 2015/ Tim Guenther and Christian Mainka
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Functions to decompress and compress Base64 content with zip deflate/inflate.
 * @author Christian Mainka
 * @version 1.0
 */

// Thanks to
// http://qupera.blogspot.de/2013/02/howto-compress-and-uncompress-java-byte.html
public class Compression {
    
        /**
	 * Compress given bytes with zip deflate.
	 * @param data The content to compress.
         * @throws IOException For the ByteArrayOutputStream().
	 * @return The compressed content.
	 */

	public static byte[] compress(byte[] data) throws IOException {
		Deflater deflater = new Deflater(9, Boolean.TRUE);
		deflater.setInput(data);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);

		deflater.finish();
		byte[] buffer = new byte[1024];
		while (!deflater.finished()) {
			int count = deflater.deflate(buffer); // returns the generated code... index
			outputStream.write(buffer, 0, count);
		}
		outputStream.close();
		byte[] output = outputStream.toByteArray();

		deflater.end();

		return output;
	}
        
        /**
	 * Decompress given bytes with zip inflate.
	 * @param data The content to decompress.
         * @throws IOException For the ByteArrayOutputStream().
         * @throws DataFormatException For the Inflater().
	 * @return The decompressed content.
	 */

	public static byte[] decompress(byte[] data) throws IOException, DataFormatException {
		Inflater inflater = new Inflater(Boolean.TRUE);
		inflater.setInput(data);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
		byte[] buffer = new byte[1024];
		while (!inflater.finished()) {
			int count = inflater.inflate(buffer);
			outputStream.write(buffer, 0, count);
		}
		outputStream.close();
		byte[] output = outputStream.toByteArray();

		inflater.end();

		return output;
	}
}
