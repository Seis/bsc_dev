package org.tomaszewski.utils.Logger;

public class MyLevel extends java.util.logging.Level {
    public static final MyLevel PLS_DONT = new MyLevel("WHY_YOU'RE_TRYING_TO_BREAK_ME", Integer.MAX_VALUE-1);

    protected MyLevel(String name, int value) {
        super(name, value);
    }
}
