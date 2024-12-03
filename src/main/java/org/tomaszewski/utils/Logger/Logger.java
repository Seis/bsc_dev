package org.tomaszewski.utils.Logger;

import org.tomaszewski.utils.Utils;
import java.util.logging.Level;

public class Logger {
    public static final Level DEBUG_LEVEL = Level.parse(Utils.env.get("DEBUG_LEVEL", "OFF"));

    /**
     * True if FINE, FINER, FINEST, ALL (500 or less).
     */
    public static final boolean DEBUG = (DEBUG_LEVEL.intValue() <= Level.FINE.intValue());

    public static void log(Level level, String message) {
        if (DEBUG_LEVEL != Level.OFF){
            System.out.println("    " + level.toString() + " - " + message);
        }
    }
    public static void log(Level level, String message, Exception exception) {
        if (DEBUG_LEVEL != Level.OFF){
            System.out.println("    " + level.toString() + " - " + message);
            System.out.println("        " + exception.getMessage());
        }
    }
}