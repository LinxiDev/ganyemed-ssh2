package ch.ethz.ssh2.sftp;

public class Packet {
   public static final int SSH_FXP_INIT = 1;
   public static final int SSH_FXP_VERSION = 2;
   public static final int SSH_FXP_OPEN = 3;
   public static final int SSH_FXP_CLOSE = 4;
   public static final int SSH_FXP_READ = 5;
   public static final int SSH_FXP_WRITE = 6;
   public static final int SSH_FXP_LSTAT = 7;
   public static final int SSH_FXP_FSTAT = 8;
   public static final int SSH_FXP_SETSTAT = 9;
   public static final int SSH_FXP_FSETSTAT = 10;
   public static final int SSH_FXP_OPENDIR = 11;
   public static final int SSH_FXP_READDIR = 12;
   public static final int SSH_FXP_REMOVE = 13;
   public static final int SSH_FXP_MKDIR = 14;
   public static final int SSH_FXP_RMDIR = 15;
   public static final int SSH_FXP_REALPATH = 16;
   public static final int SSH_FXP_STAT = 17;
   public static final int SSH_FXP_RENAME = 18;
   public static final int SSH_FXP_READLINK = 19;
   public static final int SSH_FXP_SYMLINK = 20;
   public static final int SSH_FXP_STATUS = 101;
   public static final int SSH_FXP_HANDLE = 102;
   public static final int SSH_FXP_DATA = 103;
   public static final int SSH_FXP_NAME = 104;
   public static final int SSH_FXP_ATTRS = 105;
   public static final int SSH_FXP_EXTENDED = 200;
   public static final int SSH_FXP_EXTENDED_REPLY = 201;

   public static String forName(int type) {
      switch(type) {
      case 1:
         return "SSH_FXP_INIT";
      case 2:
         return "SSH_FXP_VERSION";
      case 3:
         return "SSH_FXP_OPEN";
      case 4:
         return "SSH_FXP_CLOSE";
      case 5:
         return "SSH_FXP_READ";
      case 6:
         return "SSH_FXP_WRITE";
      case 7:
         return "SSH_FXP_LSTAT";
      case 8:
         return "SSH_FXP_FSTAT";
      case 9:
         return "SSH_FXP_SETSTAT";
      case 10:
         return "SSH_FXP_FSETSTAT";
      case 11:
         return "SSH_FXP_OPENDIR";
      case 12:
         return "SSH_FXP_READDIR";
      case 13:
         return "SSH_FXP_REMOVE";
      case 14:
         return "SSH_FXP_MKDIR";
      case 15:
         return "SSH_FXP_RMDIR";
      case 16:
         return "SSH_FXP_REALPATH";
      case 17:
         return "SSH_FXP_STAT";
      case 18:
         return "SSH_FXP_RENAME";
      case 19:
         return "SSH_FXP_READLINK";
      case 20:
         return "SSH_FXP_SYMLINK";
      case 101:
         return "SSH_FXP_STATUS";
      case 102:
         return "SSH_FXP_HANDLE";
      case 103:
         return "SSH_FXP_DATA";
      case 104:
         return "SSH_FXP_NAME";
      case 105:
         return "SSH_FXP_ATTRS";
      case 200:
         return "SSH_FXP_EXTENDED";
      case 201:
         return "SSH_FXP_EXTENDED_REPLY";
      default:
         return null;
      }
   }
}
