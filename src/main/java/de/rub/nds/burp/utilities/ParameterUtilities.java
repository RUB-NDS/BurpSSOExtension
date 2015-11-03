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

import burp.IParameter;
import java.util.List;
import java.util.Set;

/**
 * Functions to search parameter lists.
 * @author Christian Mainka
 * @version 1.0
 */

final public class ParameterUtilities {

        /**
	 * Search for the first appearance of a parameter in the list.
	 * @param parameterList A list of parameters with string names.
	 * @param parameterName The name of the parameter.
	 * @return true if the list contains the name otherwise false.
	 */
	public static boolean parameterListContainsParameterName(List<IParameter> parameterList, String parameterName) {
		boolean result = false;
		for (IParameter p : parameterList) {
			if (parameterName.equals(p.getName())) {
				result = true;
				break;
			}
		}
		return result;
	}

        /**
	 * Search for the first appearance of a parameter in the list.
	 * @param parameterList A list of parameters with string names.
	 * @param parameterNames A set of names for parameters.
	 * @return true if the list contains of of the given names otherwise false.
	 */
	public static boolean parameterListContainsParameterName(List<IParameter> parameterList, Set<String> parameterNames) {
		boolean result = false;
		for (IParameter p : parameterList) {
			if (parameterNames.contains(p.getName())) {
				result = true;
				break;
			}
		}
		return result;
	}

	/**
	 * Search for the first appearance of a parameter in the list.
	 * @param parameterList A list of parameters with string names.
	 * @param parameterName The name of the parameter.
	 * @return The first parameter with the given name found in the
         * parameter list, or null, if parameterName is not found.
	 */
	public static IParameter getFirstParameterByName(List<IParameter> parameterList, String parameterName) {
		IParameter result = null;
		for (IParameter p : parameterList) {
			if (parameterName.equals(p.getName())) {
				result = p;
				break;
			}
		}
		return result;
	}
}
