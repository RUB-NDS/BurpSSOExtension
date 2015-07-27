/*
 * Copyright (C) 2015 Tim Guenther
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package de.rub.guenther.tim.espresso.utilities;

import de.rub.guenther.tim.espresso.utilities.Table;
import de.rub.guenther.tim.espresso.utilities.TableEntry;
import java.util.ArrayList;

/**
 *
 * @author Tim Guenther
 */
public abstract class TableDB {
    
    //Tables - add a new table for each
    private final static ArrayList<Table> tableList = new ArrayList<Table>();
    
    public static Table getTable(String name){
        for(Table t : tableList){
            if(t.getName().equals(name)){
                return t;
            }
        }
        return null;
    }
    
    public static Table getTable(int index){
        return tableList.get(index);
    }
    
    public static void addTable(Table t){
        tableList.add(t);
    }
}
