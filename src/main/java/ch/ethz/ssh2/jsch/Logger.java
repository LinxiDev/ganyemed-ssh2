package ch.ethz.ssh2.jsch;

import java.io.StringWriter;

public interface Logger {
   public static final int DEBUG = 0;

   public static final int INFO = 1;

   public static final int WARN = 2;

   public static final int ERROR = 3;

   public static final int FATAL = 4;

   boolean isEnabled(int paramInt);

   void log(int paramInt, String paramString);

   default void log(int level, String message, Throwable cause) {
      if (!isEnabled(level))
         return;
      if (cause != null) {
         StringWriter sw = new StringWriter();
         Exception exception1 = null, exception2 = null;
      }
      log(level, message);
   }
}
