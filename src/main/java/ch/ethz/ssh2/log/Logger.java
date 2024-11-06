package ch.ethz.ssh2.log;

import java.util.logging.Level;

public class Logger {
   private java.util.logging.Logger delegate;
   public static volatile boolean enabled = false;

   public static Logger getLogger(Class<?> x) {
      return new Logger(x);
   }

   public Logger(Class<?> x) {
      this.delegate = java.util.logging.Logger.getLogger(x.getName());
   }

   public boolean isDebugEnabled() {
      return enabled && this.delegate.isLoggable(Level.FINER);
   }

   public void debug(String message) {
      if (enabled) {
         this.delegate.fine(message);
      }

   }

   public boolean isInfoEnabled() {
      return enabled && this.delegate.isLoggable(Level.FINE);
   }

   public void info(String message) {
      if (enabled) {
         this.delegate.info(message);
      }

   }

   public boolean isWarningEnabled() {
      return enabled && this.delegate.isLoggable(Level.WARNING);
   }

   public void warning(String message) {
      if (enabled) {
         this.delegate.warning(message);
      }

   }
}
