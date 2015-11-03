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
package de.rub.nds.burp.utilities.table;

import java.util.ArrayList;

/**
 * A database for all Tables.
 * @author Tim Guenther
 * @version 1.0
 */
public abstract class TableDB {
    
    //Tables - add a new table for each
    private final static ArrayList<Table> tableList = new ArrayList<Table>();
    
    /**
     * Get the table by name.
     * @param id The name of the table.
     * @return The table with the given name, otherwise null.
     */
    public static Table getTable(String id){
        for(Table t : tableList){
            if(t.getID().equals(id)){
                return t;
            }
        }
        return null;
    }
    
    /**
     * Get the table by index.
     * @param index Index of the table.
     * @return The table at the position of the index.
     */
    public static Table getTable(int index){
        return tableList.get(index);
    }
    
    /**
     * Add new table to the list.
     * @param t The new table.
     * @return True if successfully, false otherwise.
     */
    public static boolean addTable(Table t){
        try{
            tableList.add(t);
        } catch (Exception e) {
            return false;
        }
        return true;
    }
    
    /**
     * Remove the a table.
     * @param t The table.
     * @return True if table is removed, false otherwise.
     */
    public static boolean removeTable(Table t){
        try{
            tableList.remove(t);
        } catch (Exception e) {
            return false;
        }
        return true;
    }
    
    /**
     * Remove all tables
     * @return True if all tables are removed.
     */
    public static boolean clear(){
        try{
            tableList.clear();
        } catch (Exception e) {
            return false;
        }
        return true;
    }
    
    /**
     * Get the count of the tables
     * @return The count.
     */
    public static int size(){
        return tableList.size();
    }
}
