package ch.ethz.ssh2.util;

import ch.ethz.ssh2.log.Logger;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;

public class TimeoutService {
   private static final Logger log = Logger.getLogger(TimeoutService.class);
   private static final LinkedList<TimeoutService.TimeoutToken> todolist = new LinkedList();
   private static Thread timeoutThread = null;

   public static TimeoutService.TimeoutToken addTimeoutHandler(long runTime, Runnable handler) {
      TimeoutService.TimeoutToken token = new TimeoutService.TimeoutToken(runTime, handler, (TimeoutService.TimeoutToken)null);
      synchronized(todolist) {
         todolist.add(token);
         Collections.sort(todolist, new Comparator<TimeoutService.TimeoutToken>() {
            public int compare(TimeoutService.TimeoutToken o1, TimeoutService.TimeoutToken o2) {
               if (o1.runTime > o2.runTime) {
                  return 1;
               } else {
                  return o1.runTime == o2.runTime ? 0 : -1;
               }
            }
         });
         if (timeoutThread != null) {
            timeoutThread.interrupt();
         } else {
            timeoutThread = new TimeoutService.TimeoutThread((TimeoutService.TimeoutThread)null);
            timeoutThread.setDaemon(true);
            timeoutThread.start();
         }

         return token;
      }
   }

   public static void cancelTimeoutHandler(TimeoutService.TimeoutToken token) {
      synchronized(todolist) {
         todolist.remove(token);
         if (timeoutThread != null) {
            timeoutThread.interrupt();
         }

      }
   }

   private static class TimeoutThread extends Thread {
      private TimeoutThread() {
      }

      public void run() {
         synchronized(TimeoutService.todolist) {
            while(TimeoutService.todolist.size() != 0) {
               long now = System.currentTimeMillis();
               TimeoutService.TimeoutToken tt = (TimeoutService.TimeoutToken)TimeoutService.todolist.getFirst();
               if (tt.runTime > now) {
                  try {
                     TimeoutService.todolist.wait(tt.runTime - now);
                  } catch (InterruptedException var7) {
                  }
               } else {
                  TimeoutService.todolist.removeFirst();

                  try {
                     tt.handler.run();
                  } catch (Exception var8) {
                     StringWriter sw = new StringWriter();
                     var8.printStackTrace(new PrintWriter(sw));
                     TimeoutService.log.warning("Exeception in Timeout handler:" + var8.getMessage() + "(" + sw.toString() + ")");
                  }
               }
            }

            TimeoutService.timeoutThread = null;
         }
      }

      // $FF: synthetic method
      TimeoutThread(TimeoutService.TimeoutThread var1) {
         this();
      }
   }

   public static class TimeoutToken {
      private long runTime;
      private Runnable handler;

      private TimeoutToken(long runTime, Runnable handler) {
         this.runTime = runTime;
         this.handler = handler;
      }

      // $FF: synthetic method
      TimeoutToken(long var1, Runnable var3, TimeoutService.TimeoutToken var4) {
         this(var1, var3);
      }
   }
}
