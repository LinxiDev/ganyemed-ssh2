package ch.ethz.ssh2.channel;

import ch.ethz.ssh2.PtySettings;
import ch.ethz.ssh2.ServerConnectionCallback;
import ch.ethz.ssh2.ServerSessionCallback;
import ch.ethz.ssh2.log.Logger;
import ch.ethz.ssh2.packets.PacketChannelFailure;
import ch.ethz.ssh2.packets.PacketChannelOpenConfirmation;
import ch.ethz.ssh2.packets.PacketChannelOpenFailure;
import ch.ethz.ssh2.packets.PacketChannelSuccess;
import ch.ethz.ssh2.packets.PacketGlobalCancelForwardRequest;
import ch.ethz.ssh2.packets.PacketGlobalForwardRequest;
import ch.ethz.ssh2.packets.PacketOpenDirectTCPIPChannel;
import ch.ethz.ssh2.packets.PacketOpenSessionChannel;
import ch.ethz.ssh2.packets.PacketSessionExecCommand;
import ch.ethz.ssh2.packets.PacketSessionPtyRequest;
import ch.ethz.ssh2.packets.PacketSessionStartShell;
import ch.ethz.ssh2.packets.PacketSessionSubsystemRequest;
import ch.ethz.ssh2.packets.PacketSessionX11Request;
import ch.ethz.ssh2.packets.PacketWindowChange;
import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.server.ServerConnectionState;
import ch.ethz.ssh2.transport.MessageHandler;
import ch.ethz.ssh2.transport.TransportManager;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ChannelManager implements MessageHandler {
   private static final Logger log = Logger.getLogger(ChannelManager.class);

   private final ServerConnectionState server_state;

   private final TransportManager tm;

   private final Map<String, X11ServerData> x11_magic_cookies = new HashMap<>();

   private final List<Channel> channels = new ArrayList<>();

   private int nextLocalChannel = 100;

   private boolean shutdown = false;

   private int globalSuccessCounter = 0;

   private int globalFailedCounter = 0;

   private final Map<Integer, RemoteForwardingData> remoteForwardings = new HashMap<>();

   private final List<IChannelWorkerThread> listenerThreads = new ArrayList<>();

   private boolean listenerThreadsAllowed = true;

   public ChannelManager(TransportManager tm) {
      this.server_state = null;
      this.tm = tm;
      tm.registerMessageHandler(this, 80, 100);
   }

   public ChannelManager(ServerConnectionState state) {
      this.server_state = state;
      this.tm = (TransportManager)state.tm;
      this.tm.registerMessageHandler(this, 80, 100);
   }

   private Channel getChannel(int id) {
      synchronized (this.channels) {
         for (Channel c : this.channels) {
            if (c.localID == id)
               return c;
         }
      }
      return null;
   }

   private void removeChannel(int id) {
      synchronized (this.channels) {
         for (Channel c : this.channels) {
            if (c.localID == id) {
               this.channels.remove(c);
               break;
            }
         }
      }
   }

   private int addChannel(Channel c) {
      synchronized (this.channels) {
         this.channels.add(c);
         return this.nextLocalChannel++;
      }
   }

   private void waitUntilChannelOpen(Channel c) throws IOException {
      synchronized (c) {
         while (c.state == 1) {
            try {
               c.wait();
            } catch (InterruptedException e) {
               throw new InterruptedIOException(e.getMessage());
            }
         }
         if (c.state != 2) {
            removeChannel(c.localID);
            String detail = c.getReasonClosed();
            if (detail == null)
               detail = "state: " + c.state;
            throw new IOException("Could not open channel (" + detail + ")");
         }
      }
   }

   private void waitForGlobalSuccessOrFailure() throws IOException {
      synchronized (this.channels) {
         while (this.globalSuccessCounter == 0 && this.globalFailedCounter == 0) {
            if (this.shutdown)
               throw new IOException("The connection is being shutdown");
            try {
               this.channels.wait();
            } catch (InterruptedException e) {
               throw new InterruptedIOException(e.getMessage());
            }
         }
         if (this.globalFailedCounter == 0 && this.globalSuccessCounter == 1)
            return;
         if (this.globalFailedCounter == 1 && this.globalSuccessCounter == 0)
            throw new IOException("The server denied the request (did you enable port forwarding?)");
         throw new IOException("Illegal state. The server sent " + this.globalSuccessCounter +
                 " SSH_MSG_REQUEST_SUCCESS and " + this.globalFailedCounter + " SSH_MSG_REQUEST_FAILURE messages.");
      }
   }

   private void waitForChannelSuccessOrFailure(Channel c) throws IOException {
      synchronized (c) {
         while (c.successCounter == 0 && c.failedCounter == 0) {
            if (c.state != 2) {
               String detail = c.getReasonClosed();
               if (detail == null)
                  detail = "state: " + c.state;
               throw new IOException("This SSH2 channel is not open (" + detail + ")");
            }
            try {
               c.wait();
            } catch (InterruptedException ignore) {
               throw new InterruptedIOException();
            }
         }
         if (c.failedCounter == 0 && c.successCounter == 1)
            return;
         if (c.failedCounter == 1 && c.successCounter == 0)
            throw new IOException("The server denied the request.");
         throw new IOException("Illegal state. The server sent " + c.successCounter +
                 " SSH_MSG_CHANNEL_SUCCESS and " + c.failedCounter + " SSH_MSG_CHANNEL_FAILURE messages.");
      }
   }

   public void registerX11Cookie(String hexFakeCookie, X11ServerData data) {
      synchronized (this.x11_magic_cookies) {
         this.x11_magic_cookies.put(hexFakeCookie, data);
      }
   }

   public void unRegisterX11Cookie(String hexFakeCookie, boolean killChannels) {
      if (hexFakeCookie == null)
         throw new IllegalStateException("hexFakeCookie may not be null");
      synchronized (this.x11_magic_cookies) {
         this.x11_magic_cookies.remove(hexFakeCookie);
      }
      if (!killChannels)
         return;
      log.debug("Closing all X11 channels for the given fake cookie");
      List<Channel> channel_copy = new ArrayList<>();
      synchronized (this.channels) {
         channel_copy.addAll(this.channels);
      }
      for (Channel c : channel_copy) {
         synchronized (c) {
            if (!hexFakeCookie.equals(c.hexX11FakeCookie))
               continue;
         }
         try {
            closeChannel(c, "Closing X11 channel since the corresponding session is closing", true);
         } catch (IOException iOException) {}
      }
   }

   public X11ServerData checkX11Cookie(String hexFakeCookie) {
      synchronized (this.x11_magic_cookies) {
         if (hexFakeCookie != null)
            return this.x11_magic_cookies.get(hexFakeCookie);
      }
      return null;
   }

   public void closeAllChannels() {
      log.debug("Closing all channels");
      List<Channel> channel_copy = new ArrayList<>();
      synchronized (this.channels) {
         channel_copy.addAll(this.channels);
      }
      for (Channel c : channel_copy) {
         try {
            closeChannel(c, "Closing all channels", true);
         } catch (IOException iOException) {}
      }
   }

   public void closeChannel(Channel c, String reason, boolean force) throws IOException {
      byte[] msg = new byte[5];
      synchronized (c) {
         if (force) {
            c.state = 4;
            c.EOF = true;
         }
         c.setReasonClosed(reason);
         msg[0] = 97;
         msg[1] = (byte)(c.remoteID >> 24);
         msg[2] = (byte)(c.remoteID >> 16);
         msg[3] = (byte)(c.remoteID >> 8);
         msg[4] = (byte)c.remoteID;
         c.notifyAll();
      }
      synchronized (c.channelSendLock) {
         if (c.closeMessageSent)
            return;
         this.tm.sendMessage(msg);
         c.closeMessageSent = true;
      }
      log.debug("Sent SSH_MSG_CHANNEL_CLOSE (channel " + c.localID + ")");
   }

   public void sendEOF(Channel c) throws IOException {
      byte[] msg = new byte[5];
      synchronized (c) {
         if (c.state != 2)
            return;
         msg[0] = 96;
         msg[1] = (byte)(c.remoteID >> 24);
         msg[2] = (byte)(c.remoteID >> 16);
         msg[3] = (byte)(c.remoteID >> 8);
         msg[4] = (byte)c.remoteID;
      }
      synchronized (c.channelSendLock) {
         if (c.closeMessageSent)
            return;
         this.tm.sendMessage(msg);
      }
      log.debug("Sent EOF (Channel " + c.localID + "/" + c.remoteID + ")");
   }

   public void sendOpenConfirmation(Channel c) throws IOException {
      PacketChannelOpenConfirmation pcoc = null;
      synchronized (c) {
         if (c.state != 1)
            return;
         c.state = 2;
         pcoc = new PacketChannelOpenConfirmation(c.remoteID, c.localID, c.localWindow, c.localMaxPacketSize);
      }
      synchronized (c.channelSendLock) {
         if (c.closeMessageSent)
            return;
         this.tm.sendMessage(pcoc.getPayload());
      }
   }

   public void sendData(Channel c, byte[] buffer, int pos, int len) throws IOException {
      while (len > 0) {
         byte[] msg;
         int thislen = 0;
         synchronized (c) {
            while (true) {
               if (c.state == 4)
                  throw new ChannelClosedException("SSH channel is closed. (" + c.getReasonClosed() + ")");
               if (c.state != 2)
                  throw new ChannelClosedException("SSH channel in strange state. (" + c.state + ")");
               if (c.remoteWindow != 0L)
                  break;
               try {
                  c.wait();
               } catch (InterruptedException e) {
                  throw new InterruptedIOException(e.getMessage());
               }
            }
            thislen = (c.remoteWindow >= len) ? len : (int)c.remoteWindow;
            int estimatedMaxDataLen = c.remoteMaxPacketSize - this.tm.getPacketOverheadEstimate() + 9;
            if (estimatedMaxDataLen <= 0)
               estimatedMaxDataLen = 1;
            if (thislen > estimatedMaxDataLen)
               thislen = estimatedMaxDataLen;
            c.remoteWindow -= thislen;
            msg = new byte[9 + thislen];
            msg[0] = 94;
            msg[1] = (byte)(c.remoteID >> 24);
            msg[2] = (byte)(c.remoteID >> 16);
            msg[3] = (byte)(c.remoteID >> 8);
            msg[4] = (byte)c.remoteID;
            msg[5] = (byte)(thislen >> 24);
            msg[6] = (byte)(thislen >> 16);
            msg[7] = (byte)(thislen >> 8);
            msg[8] = (byte)thislen;
            System.arraycopy(buffer, pos, msg, 9, thislen);
         }
         synchronized (c.channelSendLock) {
            if (c.closeMessageSent)
               throw new ChannelClosedException("SSH channel is closed. (" + c.getReasonClosed() + ")");
            this.tm.sendMessage(msg);
         }
         pos += thislen;
         len -= thislen;
      }
   }

   public int requestGlobalForward(String bindAddress, int bindPort, String targetAddress, int targetPort) throws IOException {
      RemoteForwardingData rfd = new RemoteForwardingData();
      rfd.bindAddress = bindAddress;
      rfd.bindPort = bindPort;
      rfd.targetAddress = targetAddress;
      rfd.targetPort = targetPort;
      synchronized (this.remoteForwardings) {
         Integer key = Integer.valueOf(bindPort);
         if (this.remoteForwardings.get(key) != null)
            throw new IOException("There is already a forwarding for remote port " + bindPort);
         this.remoteForwardings.put(key, rfd);
      }
      synchronized (this.channels) {
         this.globalSuccessCounter = this.globalFailedCounter = 0;
      }
      PacketGlobalForwardRequest pgf = new PacketGlobalForwardRequest(true, bindAddress, bindPort);
      this.tm.sendMessage(pgf.getPayload());
      log.debug("Requesting a remote forwarding ('" + bindAddress + "', " + bindPort + ")");
      try {
         waitForGlobalSuccessOrFailure();
      } catch (IOException e) {
         synchronized (this.remoteForwardings) {
            this.remoteForwardings.remove(rfd);
         }
         throw e;
      }
      return bindPort;
   }

   public void requestCancelGlobalForward(int bindPort) throws IOException {
      RemoteForwardingData rfd = null;
      synchronized (this.remoteForwardings) {
         rfd = this.remoteForwardings.get(Integer.valueOf(bindPort));
         if (rfd == null)
            throw new IOException("Sorry, there is no known remote forwarding for remote port " + bindPort);
      }
      synchronized (this.channels) {
         this.globalSuccessCounter = this.globalFailedCounter = 0;
      }
      PacketGlobalCancelForwardRequest pgcf = new PacketGlobalCancelForwardRequest(true, rfd.bindAddress,
              rfd.bindPort);
      this.tm.sendMessage(pgcf.getPayload());
      log.debug("Requesting cancelation of remote forward ('" + rfd.bindAddress + "', " + rfd.bindPort + ")");
      waitForGlobalSuccessOrFailure();
      synchronized (this.remoteForwardings) {
         this.remoteForwardings.remove(rfd);
      }
   }

   public void registerThread(IChannelWorkerThread thr) throws IOException {
      synchronized (this.listenerThreads) {
         if (!this.listenerThreadsAllowed)
            throw new IOException("Too late, this connection is closed.");
         this.listenerThreads.add(thr);
      }
   }

   public Channel openDirectTCPIPChannel(String host_to_connect, int port_to_connect, String originator_IP_address, int originator_port) throws IOException {
      Channel c = new Channel(this);
      synchronized (c) {
         c.localID = addChannel(c);
      }
      PacketOpenDirectTCPIPChannel dtc = new PacketOpenDirectTCPIPChannel(c.localID, c.localWindow,
              c.localMaxPacketSize, host_to_connect, port_to_connect, originator_IP_address, originator_port);
      this.tm.sendMessage(dtc.getPayload());
      waitUntilChannelOpen(c);
      return c;
   }

   public Channel openSessionChannel() throws IOException {
      Channel c = new Channel(this);
      synchronized (c) {
         c.localID = addChannel(c);
      }
      log.debug("Sending SSH_MSG_CHANNEL_OPEN (Channel " + c.localID + ")");
      PacketOpenSessionChannel smo = new PacketOpenSessionChannel(c.localID, c.localWindow, c.localMaxPacketSize);
      this.tm.sendMessage(smo.getPayload());
      waitUntilChannelOpen(c);
      return c;
   }

   public void requestPTY(Channel c, String term, int term_width_characters, int term_height_characters, int term_width_pixels, int term_height_pixels, byte[] terminal_modes) throws IOException {
      PacketSessionPtyRequest spr;
      synchronized (c) {
         if (c.state != 2)
            throw new IOException("Cannot request PTY on this channel (" + c.getReasonClosed() + ")");
         spr = new PacketSessionPtyRequest(c.remoteID, true, term, term_width_characters, term_height_characters,
                 term_width_pixels, term_height_pixels, terminal_modes);
         c.successCounter = c.failedCounter = 0;
      }
      synchronized (c.channelSendLock) {
         if (c.closeMessageSent)
            throw new IOException("Cannot request PTY on this channel (" + c.getReasonClosed() + ")");
         this.tm.sendMessage(spr.getPayload());
      }
      try {
         waitForChannelSuccessOrFailure(c);
      } catch (IOException e) {
         throw new IOException("PTY request failed", e);
      }
   }

   public void requestWindowChange(Channel c, int term_width_characters, int term_height_characters, int term_width_pixels, int term_height_pixels) throws IOException {
      PacketWindowChange pwc;
      synchronized (c) {
         if (c.state != 2)
            throw new IOException("Cannot request window-change on this channel (" + c.getReasonClosed() + ")");
         pwc = new PacketWindowChange(c.remoteID, term_width_characters, term_height_characters,
                 term_width_pixels, term_height_pixels);
         c.successCounter = c.failedCounter = 0;
      }
      synchronized (c.channelSendLock) {
         if (c.closeMessageSent)
            throw new IOException("Cannot request window-change on this channel (" + c.getReasonClosed() + ")");
         this.tm.sendMessage(pwc.getPayload());
      }
      try {
         waitForChannelSuccessOrFailure(c);
      } catch (IOException e) {
         throw new IOException("The window-change request failed.", e);
      }
   }

   public void requestX11(Channel c, boolean singleConnection, String x11AuthenticationProtocol, String x11AuthenticationCookie, int x11ScreenNumber) throws IOException {
      PacketSessionX11Request psr;
      synchronized (c) {
         if (c.state != 2)
            throw new IOException("Cannot request X11 on this channel (" + c.getReasonClosed() + ")");
         psr = new PacketSessionX11Request(c.remoteID, true, singleConnection, x11AuthenticationProtocol,
                 x11AuthenticationCookie, x11ScreenNumber);
         c.successCounter = c.failedCounter = 0;
      }
      synchronized (c.channelSendLock) {
         if (c.closeMessageSent)
            throw new IOException("Cannot request X11 on this channel (" + c.getReasonClosed() + ")");
         this.tm.sendMessage(psr.getPayload());
      }
      log.debug("Requesting X11 forwarding (Channel " + c.localID + "/" + c.remoteID + ")");
      try {
         waitForChannelSuccessOrFailure(c);
      } catch (IOException e) {
         throw new IOException("The X11 request failed.", e);
      }
   }

   public void requestSubSystem(Channel c, String subSystemName) throws IOException {
      PacketSessionSubsystemRequest ssr;
      synchronized (c) {
         if (c.state != 2)
            throw new IOException("Cannot request subsystem on this channel (" + c.getReasonClosed() + ")");
         ssr = new PacketSessionSubsystemRequest(c.remoteID, true, subSystemName);
         c.successCounter = c.failedCounter = 0;
      }
      synchronized (c.channelSendLock) {
         if (c.closeMessageSent)
            throw new IOException("Cannot request subsystem on this channel (" + c.getReasonClosed() + ")");
         this.tm.sendMessage(ssr.getPayload());
      }
      try {
         waitForChannelSuccessOrFailure(c);
      } catch (IOException e) {
         throw new IOException("The subsystem request failed.", e);
      }
   }

   public void requestExecCommand(Channel c, String cmd) throws IOException {
      requestExecCommand(c, cmd, null);
   }

   public void requestExecCommand(Channel c, String cmd, String charsetName) throws IOException {
      PacketSessionExecCommand sm;
      synchronized (c) {
         if (c.state != 2)
            throw new IOException("Cannot execute command on this channel (" + c.getReasonClosed() + ")");
         sm = new PacketSessionExecCommand(c.remoteID, true, cmd);
         c.successCounter = c.failedCounter = 0;
      }
      synchronized (c.channelSendLock) {
         if (c.closeMessageSent)
            throw new IOException("Cannot execute command on this channel (" + c.getReasonClosed() + ")");
         this.tm.sendMessage(sm.getPayload(charsetName));
      }
      log.debug("Executing command (channel " + c.localID + ", '" + cmd + "')");
      try {
         waitForChannelSuccessOrFailure(c);
      } catch (IOException e) {
         throw new IOException("The execute request failed.", e);
      }
   }

   public void requestShell(Channel c) throws IOException {
      PacketSessionStartShell sm;
      synchronized (c) {
         if (c.state != 2)
            throw new IOException("Cannot start shell on this channel (" + c.getReasonClosed() + ")");
         sm = new PacketSessionStartShell(c.remoteID, true);
         c.successCounter = c.failedCounter = 0;
      }
      synchronized (c.channelSendLock) {
         if (c.closeMessageSent)
            throw new IOException("Cannot start shell on this channel (" + c.getReasonClosed() + ")");
         this.tm.sendMessage(sm.getPayload());
      }
      try {
         waitForChannelSuccessOrFailure(c);
      } catch (IOException e) {
         throw new IOException("The shell request failed.", e);
      }
   }

   public void msgChannelExtendedData(byte[] msg, int msglen) throws IOException {
      if (msglen <= 13)
         throw new IOException("SSH_MSG_CHANNEL_EXTENDED_DATA message has wrong size (" + msglen + ")");
      int id = (msg[1] & 0xFF) << 24 | (msg[2] & 0xFF) << 16 | (msg[3] & 0xFF) << 8 | msg[4] & 0xFF;
      int dataType = (msg[5] & 0xFF) << 24 | (msg[6] & 0xFF) << 16 | (msg[7] & 0xFF) << 8 | msg[8] & 0xFF;
      int len = (msg[9] & 0xFF) << 24 | (msg[10] & 0xFF) << 16 | (msg[11] & 0xFF) << 8 | msg[12] & 0xFF;
      Channel c = getChannel(id);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_EXTENDED_DATA message for non-existent channel " + id);
      if (dataType != 1)
         throw new IOException("SSH_MSG_CHANNEL_EXTENDED_DATA message has unknown type (" + dataType + ")");
      if (len != msglen - 13)
         throw new IOException("SSH_MSG_CHANNEL_EXTENDED_DATA message has wrong len (calculated " + (msglen - 13) +
                 ", got " + len + ")");
      log.debug("Got SSH_MSG_CHANNEL_EXTENDED_DATA (channel " + id + ", " + len + ")");
      synchronized (c) {
         if (c.state == 4)
            return;
         if (c.state != 2)
            throw new IOException("Got SSH_MSG_CHANNEL_EXTENDED_DATA, but channel is not in correct state (" +
                    c.state + ")");
         if (c.localWindow < len)
            throw new IOException("Remote sent too much data, does not fit into window.");
         c.localWindow -= len;
         System.arraycopy(msg, 13, c.stderrBuffer, c.stderrWritepos, len);
         c.stderrWritepos += len;
         c.notifyAll();
      }
   }

   public int waitForCondition(Channel c, long timeout, int condition_mask) throws IOException {
      long end_time = 0L;
      boolean end_time_set = false;
      synchronized (c) {
         while (true) {
            int current_cond = 0;
            int stdoutAvail = c.stdoutWritepos - c.stdoutReadpos;
            int stderrAvail = c.stderrWritepos - c.stderrReadpos;
            if (stdoutAvail > 0)
               current_cond |= 0x4;
            if (stderrAvail > 0)
               current_cond |= 0x8;
            if (c.EOF)
               current_cond |= 0x10;
            if (c.getExitStatus() != null)
               current_cond |= 0x20;
            if (c.getExitSignal() != null)
               current_cond |= 0x40;
            if (c.state == 4)
               return current_cond | 0x2 | 0x10;
            if ((current_cond & condition_mask) != 0)
               return current_cond;
            if (timeout > 0L)
               if (!end_time_set) {
                  end_time = System.currentTimeMillis() + timeout;
                  end_time_set = true;
               } else {
                  timeout = end_time - System.currentTimeMillis();
                  if (timeout <= 0L)
                     return current_cond | 0x1;
               }
            try {
               if (timeout > 0L) {
                  c.wait(timeout);
                  continue;
               }
               c.wait();
            } catch (InterruptedException e) {
               throw new InterruptedIOException(e.getMessage());
            }
         }
      }
   }

   public int getAvailable(Channel c, boolean extended) throws IOException {
      synchronized (c) {
         int avail;
         if (extended) {
            avail = c.stderrWritepos - c.stderrReadpos;
         } else {
            avail = c.stdoutWritepos - c.stdoutReadpos;
         }
         return (avail > 0) ? avail : (c.EOF ? -1 : 0);
      }
   }

   public int getChannelData(Channel c, boolean extended, byte[] target, int off, int len) throws IOException {
      int copylen = 0;
      int increment = 0;
      int remoteID = 0;
      int localID = 0;
      synchronized (c) {
         int stdoutAvail = 0;
         int stderrAvail = 0;
         while (true) {
            stdoutAvail = c.stdoutWritepos - c.stdoutReadpos;
            stderrAvail = c.stderrWritepos - c.stderrReadpos;
            if (!extended && stdoutAvail != 0)
               break;
            if (extended && stderrAvail != 0)
               break;
            if (c.EOF || c.state != 2)
               return -1;
            try {
               c.wait();
            } catch (InterruptedException e) {
               throw new InterruptedIOException(e.getMessage());
            }
         }
         if (!extended) {
            copylen = (stdoutAvail > len) ? len : stdoutAvail;
            System.arraycopy(c.stdoutBuffer, c.stdoutReadpos, target, off, copylen);
            c.stdoutReadpos += copylen;
            if (c.stdoutReadpos != c.stdoutWritepos)
               System.arraycopy(c.stdoutBuffer, c.stdoutReadpos, c.stdoutBuffer, 0, c.stdoutWritepos -
                       c.stdoutReadpos);
            c.stdoutWritepos -= c.stdoutReadpos;
            c.stdoutReadpos = 0;
         } else {
            copylen = (stderrAvail > len) ? len : stderrAvail;
            System.arraycopy(c.stderrBuffer, c.stderrReadpos, target, off, copylen);
            c.stderrReadpos += copylen;
            if (c.stderrReadpos != c.stderrWritepos)
               System.arraycopy(c.stderrBuffer, c.stderrReadpos, c.stderrBuffer, 0, c.stderrWritepos -
                       c.stderrReadpos);
            c.stderrWritepos -= c.stderrReadpos;
            c.stderrReadpos = 0;
         }
         if (c.state != 2)
            return copylen;
         if (c.localWindow < 98304) {
            int minFreeSpace = Math.min(196608 - c.stdoutWritepos,
                    196608 - c.stderrWritepos);
            increment = minFreeSpace - c.localWindow;
            c.localWindow = minFreeSpace;
         }
         remoteID = c.remoteID;
         localID = c.localID;
      }
      if (increment > 0) {
         log.debug("Sending SSH_MSG_CHANNEL_WINDOW_ADJUST (channel " + localID + ", " + increment + ")");
         synchronized (c.channelSendLock) {
            byte[] msg = c.msgWindowAdjust;
            msg[0] = 93;
            msg[1] = (byte)(remoteID >> 24);
            msg[2] = (byte)(remoteID >> 16);
            msg[3] = (byte)(remoteID >> 8);
            msg[4] = (byte)remoteID;
            msg[5] = (byte)(increment >> 24);
            msg[6] = (byte)(increment >> 16);
            msg[7] = (byte)(increment >> 8);
            msg[8] = (byte)increment;
            if (!c.closeMessageSent)
               this.tm.sendMessage(msg);
         }
      }
      return copylen;
   }

   public void msgChannelData(byte[] msg, int msglen) throws IOException {
      if (msglen <= 9)
         throw new IOException("SSH_MSG_CHANNEL_DATA message has wrong size (" + msglen + ")");
      int id = (msg[1] & 0xFF) << 24 | (msg[2] & 0xFF) << 16 | (msg[3] & 0xFF) << 8 | msg[4] & 0xFF;
      int len = (msg[5] & 0xFF) << 24 | (msg[6] & 0xFF) << 16 | (msg[7] & 0xFF) << 8 | msg[8] & 0xFF;
      Channel c = getChannel(id);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_DATA message for non-existent channel " + id);
      if (len != msglen - 9)
         throw new IOException("SSH_MSG_CHANNEL_DATA message has wrong len (calculated " + (msglen - 9) + ", got " +
                 len + ")");
      log.debug("Got SSH_MSG_CHANNEL_DATA (channel " + id + ", " + len + ")");
      synchronized (c) {
         if (c.state == 4)
            return;
         if (c.state != 2)
            throw new IOException("Got SSH_MSG_CHANNEL_DATA, but channel is not in correct state (" + c.state + ")");
         if (c.localWindow < len)
            throw new IOException("Remote sent too much data, does not fit into window.");
         c.localWindow -= len;
         System.arraycopy(msg, 9, c.stdoutBuffer, c.stdoutWritepos, len);
         c.stdoutWritepos += len;
         c.notifyAll();
      }
   }

   public void msgChannelWindowAdjust(byte[] msg, int msglen) throws IOException {
      if (msglen != 9)
         throw new IOException("SSH_MSG_CHANNEL_WINDOW_ADJUST message has wrong size (" + msglen + ")");
      int id = (msg[1] & 0xFF) << 24 | (msg[2] & 0xFF) << 16 | (msg[3] & 0xFF) << 8 | msg[4] & 0xFF;
      int windowChange = (msg[5] & 0xFF) << 24 | (msg[6] & 0xFF) << 16 | (msg[7] & 0xFF) << 8 | msg[8] & 0xFF;
      Channel c = getChannel(id);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_WINDOW_ADJUST message for non-existent channel " + id);
      synchronized (c) {
         long huge = 4294967295L;
         c.remoteWindow += windowChange & 0xFFFFFFFFL;
         if (c.remoteWindow > 4294967295L)
            c.remoteWindow = 4294967295L;
         c.notifyAll();
      }
      log.debug("Got SSH_MSG_CHANNEL_WINDOW_ADJUST (channel " + id + ", " + windowChange + ")");
   }

   public void msgChannelOpen(byte[] msg, int msglen) throws IOException {
      TypesReader tr = new TypesReader(msg, 0, msglen);
      tr.readByte();
      String channelType = tr.readString();
      int remoteID = tr.readUINT32();
      int remoteWindow = tr.readUINT32();
      int remoteMaxPacketSize = tr.readUINT32();
      if ("x11".equals(channelType)) {
         synchronized (this.x11_magic_cookies) {
            if (this.x11_magic_cookies.size() == 0) {
               PacketChannelOpenFailure packetChannelOpenFailure = new PacketChannelOpenFailure(remoteID,
                       1, "X11 forwarding not activated", "");
               this.tm.sendAsynchronousMessage(packetChannelOpenFailure.getPayload());
               log.warning("Unexpected X11 request, denying it!");
               return;
            }
         }
         String remoteOriginatorAddress = tr.readString();
         int remoteOriginatorPort = tr.readUINT32();
         Channel c = new Channel(this);
         synchronized (c) {
            c.remoteID = remoteID;
            c.remoteWindow = remoteWindow & 0xFFFFFFFFL;
            c.remoteMaxPacketSize = remoteMaxPacketSize;
            c.localID = addChannel(c);
         }
         RemoteX11AcceptThread rxat = new RemoteX11AcceptThread(c, remoteOriginatorAddress, remoteOriginatorPort);
         rxat.setDaemon(true);
         rxat.start();
         return;
      }
      if ("forwarded-tcpip".equals(channelType)) {
         String remoteConnectedAddress = tr.readString();
         int remoteConnectedPort = tr.readUINT32();
         String remoteOriginatorAddress = tr.readString();
         int remoteOriginatorPort = tr.readUINT32();
         RemoteForwardingData rfd = null;
         synchronized (this.remoteForwardings) {
            rfd = this.remoteForwardings.get(Integer.valueOf(remoteConnectedPort));
         }
         if (rfd == null) {
            PacketChannelOpenFailure packetChannelOpenFailure = new PacketChannelOpenFailure(remoteID,
                    1,
                    "No thanks, unknown port in forwarded-tcpip request", "");
            this.tm.sendAsynchronousMessage(packetChannelOpenFailure.getPayload());
            log.debug("Unexpected forwarded-tcpip request, denying it!");
            return;
         }
         Channel c = new Channel(this);
         synchronized (c) {
            c.remoteID = remoteID;
            c.remoteWindow = remoteWindow & 0xFFFFFFFFL;
            c.remoteMaxPacketSize = remoteMaxPacketSize;
            c.localID = addChannel(c);
         }
         RemoteAcceptThread rat = new RemoteAcceptThread(c, remoteConnectedAddress, remoteConnectedPort,
                 remoteOriginatorAddress, remoteOriginatorPort, rfd.targetAddress, rfd.targetPort);
         rat.setDaemon(true);
         rat.start();
         return;
      }
      if (this.server_state != null && "session".equals(channelType)) {
         ServerConnectionCallback cb = null;
         synchronized (this.server_state) {
            cb = this.server_state.cb_conn;
         }
         if (cb == null) {
            this.tm.sendAsynchronousMessage((new PacketChannelOpenFailure(remoteID, 1,
                    "Sessions are currently not enabled", "en")).getPayload());
            return;
         }
         Channel c = new Channel(this);
         synchronized (c) {
            c.remoteID = remoteID;
            c.remoteWindow = remoteWindow & 0xFFFFFFFFL;
            c.remoteMaxPacketSize = remoteMaxPacketSize;
            c.localID = addChannel(c);
            c.state = 2;
            c.ss = new ServerSessionImpl(c);
         }
         PacketChannelOpenConfirmation pcoc = new PacketChannelOpenConfirmation(c.remoteID, c.localID,
                 c.localWindow, c.localMaxPacketSize);
         this.tm.sendAsynchronousMessage(pcoc.getPayload());
         c.ss.sscb = cb.acceptSession(c.ss);
         return;
      }
      PacketChannelOpenFailure pcof = new PacketChannelOpenFailure(remoteID, 3,
              "Unknown channel type", "");
      this.tm.sendAsynchronousMessage(pcof.getPayload());
      log.warning("The peer tried to open an unsupported channel type (" + channelType + ")");
   }

   private void runAsync(Runnable r) {
      Thread t = new Thread(r);
      t.start();
   }

   public void msgChannelRequest(byte[] msg, int msglen) throws IOException {
      TypesReader tr = new TypesReader(msg, 0, msglen);
      tr.readByte();
      int id = tr.readUINT32();
      Channel c = getChannel(id);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_REQUEST message for non-existent channel " + id);
      ServerSessionImpl server_session = null;
      if (this.server_state != null)
         synchronized (c) {
            server_session = c.ss;
         }
      String type = tr.readString("US-ASCII");
      boolean wantReply = tr.readBoolean();
      log.debug("Got SSH_MSG_CHANNEL_REQUEST (channel " + id + ", '" + type + "')");
      if (type.equals("exit-status")) {
         if (wantReply)
            throw new IOException(
                    "Badly formatted SSH_MSG_CHANNEL_REQUEST exit-status message, 'want reply' is true");
         int exit_status = tr.readUINT32();
         if (tr.remain() != 0)
            throw new IOException("Badly formatted SSH_MSG_CHANNEL_REQUEST message");
         synchronized (c) {
            c.exit_status = Integer.valueOf(exit_status);
            c.notifyAll();
         }
         log.debug("Got EXIT STATUS (channel " + id + ", status " + exit_status + ")");
         return;
      }
      if (this.server_state == null && type.equals("exit-signal")) {
         if (wantReply)
            throw new IOException(
                    "Badly formatted SSH_MSG_CHANNEL_REQUEST exit-signal message, 'want reply' is true");
         String signame = tr.readString("US-ASCII");
         tr.readBoolean();
         tr.readString();
         tr.readString();
         if (tr.remain() != 0)
            throw new IOException("Badly formatted SSH_MSG_CHANNEL_REQUEST message");
         synchronized (c) {
            c.exit_signal = signame;
            c.notifyAll();
         }
         log.debug("Got EXIT SIGNAL (channel " + id + ", signal " + signame + ")");
         return;
      }
      if (server_session != null && type.equals("pty-req")) {
         PtySettings pty = new PtySettings();
         pty.term = tr.readString();
         pty.term_width_characters = tr.readUINT32();
         pty.term_height_characters = tr.readUINT32();
         pty.term_width_pixels = tr.readUINT32();
         pty.term_height_pixels = tr.readUINT32();
         pty.terminal_modes = tr.readByteString();
         if (tr.remain() != 0)
            throw new IOException("Badly formatted SSH_MSG_CHANNEL_REQUEST message");
         Runnable run_after_sending_success = null;
         ServerSessionCallback sscb = server_session.getServerSessionCallback();
         if (sscb != null)
            run_after_sending_success = sscb.requestPtyReq(server_session, pty);
         if (wantReply)
            if (run_after_sending_success != null) {
               this.tm.sendAsynchronousMessage((new PacketChannelSuccess(c.remoteID)).getPayload());
            } else {
               this.tm.sendAsynchronousMessage((new PacketChannelFailure(c.remoteID)).getPayload());
            }
         if (run_after_sending_success != null)
            runAsync(run_after_sending_success);
         return;
      }
      if (server_session != null && type.equals("shell")) {
         if (tr.remain() != 0)
            throw new IOException("Badly formatted SSH_MSG_CHANNEL_REQUEST message");
         Runnable run_after_sending_success = null;
         ServerSessionCallback sscb = server_session.getServerSessionCallback();
         if (sscb != null)
            run_after_sending_success = sscb.requestShell(server_session);
         if (wantReply)
            if (run_after_sending_success != null) {
               this.tm.sendAsynchronousMessage((new PacketChannelSuccess(c.remoteID)).getPayload());
            } else {
               this.tm.sendAsynchronousMessage((new PacketChannelFailure(c.remoteID)).getPayload());
            }
         if (run_after_sending_success != null)
            runAsync(run_after_sending_success);
         return;
      }
      if (server_session != null && type.equals("exec")) {
         String command = tr.readString();
         if (tr.remain() != 0)
            throw new IOException("Badly formatted SSH_MSG_CHANNEL_REQUEST message");
         Runnable run_after_sending_success = null;
         ServerSessionCallback sscb = server_session.getServerSessionCallback();
         if (sscb != null)
            run_after_sending_success = sscb.requestExec(server_session, command);
         if (wantReply)
            if (run_after_sending_success != null) {
               this.tm.sendAsynchronousMessage((new PacketChannelSuccess(c.remoteID)).getPayload());
            } else {
               this.tm.sendAsynchronousMessage((new PacketChannelFailure(c.remoteID)).getPayload());
            }
         if (run_after_sending_success != null)
            runAsync(run_after_sending_success);
         return;
      }
      if (wantReply)
         this.tm.sendAsynchronousMessage((new PacketChannelFailure(c.remoteID)).getPayload());
      log.debug("Channel request '" + type + "' is not known, ignoring it");
   }

   public void msgChannelEOF(byte[] msg, int msglen) throws IOException {
      if (msglen != 5)
         throw new IOException("SSH_MSG_CHANNEL_EOF message has wrong size (" + msglen + ")");
      int id = (msg[1] & 0xFF) << 24 | (msg[2] & 0xFF) << 16 | (msg[3] & 0xFF) << 8 | msg[4] & 0xFF;
      Channel c = getChannel(id);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_EOF message for non-existent channel " + id);
      synchronized (c) {
         c.EOF = true;
         c.notifyAll();
      }
      log.debug("Got SSH_MSG_CHANNEL_EOF (channel " + id + ")");
   }

   public void msgChannelClose(byte[] msg, int msglen) throws IOException {
      if (msglen != 5)
         throw new IOException("SSH_MSG_CHANNEL_CLOSE message has wrong size (" + msglen + ")");
      int id = (msg[1] & 0xFF) << 24 | (msg[2] & 0xFF) << 16 | (msg[3] & 0xFF) << 8 | msg[4] & 0xFF;
      Channel c = getChannel(id);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_CLOSE message for non-existent channel " + id);
      synchronized (c) {
         c.EOF = true;
         c.state = 4;
         c.setReasonClosed("Close requested by remote");
         c.closeMessageRecv = true;
         removeChannel(c.localID);
         c.notifyAll();
      }
      log.debug("Got SSH_MSG_CHANNEL_CLOSE (channel " + id + ")");
   }

   public void msgChannelSuccess(byte[] msg, int msglen) throws IOException {
      if (msglen != 5)
         throw new IOException("SSH_MSG_CHANNEL_SUCCESS message has wrong size (" + msglen + ")");
      int id = (msg[1] & 0xFF) << 24 | (msg[2] & 0xFF) << 16 | (msg[3] & 0xFF) << 8 | msg[4] & 0xFF;
      Channel c = getChannel(id);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_SUCCESS message for non-existent channel " + id);
      synchronized (c) {
         c.successCounter++;
         c.notifyAll();
      }
      log.debug("Got SSH_MSG_CHANNEL_SUCCESS (channel " + id + ")");
   }

   public void msgChannelFailure(byte[] msg, int msglen) throws IOException {
      if (msglen != 5)
         throw new IOException("SSH_MSG_CHANNEL_FAILURE message has wrong size (" + msglen + ")");
      int id = (msg[1] & 0xFF) << 24 | (msg[2] & 0xFF) << 16 | (msg[3] & 0xFF) << 8 | msg[4] & 0xFF;
      Channel c = getChannel(id);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_FAILURE message for non-existent channel " + id);
      synchronized (c) {
         c.failedCounter++;
         c.notifyAll();
      }
      log.debug("Got SSH_MSG_CHANNEL_FAILURE (channel " + id + ")");
   }

   public void msgChannelOpenConfirmation(byte[] msg, int msglen) throws IOException {
      PacketChannelOpenConfirmation sm = new PacketChannelOpenConfirmation(msg, 0, msglen);
      Channel c = getChannel(sm.recipientChannelID);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_OPEN_CONFIRMATION message for non-existent channel " +
                 sm.recipientChannelID);
      synchronized (c) {
         if (c.state != 1)
            throw new IOException("Unexpected SSH_MSG_CHANNEL_OPEN_CONFIRMATION message for channel " +
                    sm.recipientChannelID);
         c.remoteID = sm.senderChannelID;
         c.remoteWindow = sm.initialWindowSize & 0xFFFFFFFFL;
         c.remoteMaxPacketSize = sm.maxPacketSize;
         c.state = 2;
         c.notifyAll();
      }
      log.debug("Got SSH_MSG_CHANNEL_OPEN_CONFIRMATION (channel " + sm.recipientChannelID + " / remote: " +
              sm.senderChannelID + ")");
   }

   public void msgChannelOpenFailure(byte[] msg, int msglen) throws IOException {
      if (msglen < 5)
         throw new IOException("SSH_MSG_CHANNEL_OPEN_FAILURE message has wrong size (" + msglen + ")");
      TypesReader tr = new TypesReader(msg, 0, msglen);
      tr.readByte();
      int id = tr.readUINT32();
      Channel c = getChannel(id);
      if (c == null)
         throw new IOException("Unexpected SSH_MSG_CHANNEL_OPEN_FAILURE message for non-existent channel " + id);
      int reasonCode = tr.readUINT32();
      String description = tr.readString("UTF-8");
      String reasonCodeSymbolicName = null;
      switch (reasonCode) {
         case 1:
            reasonCodeSymbolicName = "SSH_OPEN_ADMINISTRATIVELY_PROHIBITED";
            break;
         case 2:
            reasonCodeSymbolicName = "SSH_OPEN_CONNECT_FAILED";
            break;
         case 3:
            reasonCodeSymbolicName = "SSH_OPEN_UNKNOWN_CHANNEL_TYPE";
            break;
         case 4:
            reasonCodeSymbolicName = "SSH_OPEN_RESOURCE_SHORTAGE";
            break;
         default:
            reasonCodeSymbolicName = "UNKNOWN REASON CODE (" + reasonCode + ")";
            break;
      }
      StringBuilder descriptionBuffer = new StringBuilder();
      descriptionBuffer.append(description);
      for (int i = 0; i < descriptionBuffer.length(); i++) {
         char cc = descriptionBuffer.charAt(i);
         if (cc < ' ' || cc > '~') {
            descriptionBuffer.setCharAt(i, (char) 65533);
         }
      }
      synchronized (c) {
         c.EOF = true;
         c.state = 4;
         c.setReasonClosed("The server refused to open the channel (" + reasonCodeSymbolicName + ", '" +
                 descriptionBuffer.toString() + "')");
         c.notifyAll();
      }
      log.debug("Got SSH_MSG_CHANNEL_OPEN_FAILURE (channel " + id + ")");
   }

   public void msgGlobalRequest(byte[] msg, int msglen) throws IOException {
      TypesReader tr = new TypesReader(msg, 0, msglen);
      tr.readByte();
      String requestName = tr.readString();
      boolean wantReply = tr.readBoolean();
      if (wantReply) {
         byte[] reply_failure = new byte[1];
         reply_failure[0] = 82;
         this.tm.sendAsynchronousMessage(reply_failure);
      }
      log.debug("Got SSH_MSG_GLOBAL_REQUEST (" + requestName + ")");
   }

   public void msgGlobalSuccess() throws IOException {
      synchronized (this.channels) {
         this.globalSuccessCounter++;
         this.channels.notifyAll();
      }
      log.debug("Got SSH_MSG_REQUEST_SUCCESS");
   }

   public void msgGlobalFailure() throws IOException {
      synchronized (this.channels) {
         this.globalFailedCounter++;
         this.channels.notifyAll();
      }
      log.debug("Got SSH_MSG_REQUEST_FAILURE");
   }

   public void handleMessage(byte[] msg, int msglen) throws IOException {
      if (msg == null) {
         log.debug("HandleMessage: got shutdown");
         synchronized (this.listenerThreads) {
            for (IChannelWorkerThread lat : this.listenerThreads)
               lat.stopWorking();
            this.listenerThreadsAllowed = false;
         }
         synchronized (this.channels) {
            this.shutdown = true;
            for (Channel c : this.channels) {
               synchronized (c) {
                  c.EOF = true;
                  c.state = 4;
                  c.setReasonClosed("The connection is being shutdown");
                  c.closeMessageRecv = true;
                  c.notifyAll();
               }
            }
            this.channels.clear();
            this.channels.notifyAll();
            return;
         }
      }
      switch (msg[0]) {
         case 91:
            msgChannelOpenConfirmation(msg, msglen);
            return;
         case 93:
            msgChannelWindowAdjust(msg, msglen);
            return;
         case 94:
            msgChannelData(msg, msglen);
            return;
         case 95:
            msgChannelExtendedData(msg, msglen);
            return;
         case 98:
            msgChannelRequest(msg, msglen);
            return;
         case 96:
            msgChannelEOF(msg, msglen);
            return;
         case 90:
            msgChannelOpen(msg, msglen);
            return;
         case 97:
            msgChannelClose(msg, msglen);
            return;
         case 99:
            msgChannelSuccess(msg, msglen);
            return;
         case 100:
            msgChannelFailure(msg, msglen);
            return;
         case 92:
            msgChannelOpenFailure(msg, msglen);
            return;
         case 80:
            msgGlobalRequest(msg, msglen);
            return;
         case 81:
            msgGlobalSuccess();
            return;
         case 82:
            msgGlobalFailure();
            return;
      }
      throw new IOException("Cannot handle unknown channel message " + (msg[0] & 0xFF));
   }
}
