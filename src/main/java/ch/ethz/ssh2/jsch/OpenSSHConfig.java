package ch.ethz.ssh2.jsch;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.Vector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class OpenSSHConfig implements ConfigRepository {
   private static final Set<String> keysWithListAdoption;

   private final Hashtable<String, Vector<String[]>> config;

   private final Vector<String> hosts;

   static {
      keysWithListAdoption =
              (Set<String>)Stream.<String>of(new String[] { "KexAlgorithms", "Ciphers", "HostKeyAlgorithms", "MACs", "PubkeyAcceptedAlgorithms",
                      "PubkeyAcceptedKeyTypes" }).map(string -> string.toUpperCase(Locale.ROOT)).collect(Collectors.toSet());
   }

   public static OpenSSHConfig parse(String conf) throws Throwable {
      Throwable th = null;
      try {
         Reader r = new StringReader(conf);
         Throwable th2 = null;
         try {
            BufferedReader br = new BufferedReader(r);
            try {
               OpenSSHConfig openSSHConfig = new OpenSSHConfig(br);
               if (br != null) {
                  br.close();
               }
               if (r != null) {
                  r.close();
               }
               return openSSHConfig;
            } catch (Throwable th3) {
               if (br != null) {
                  br.close();
               }
               throw th3;
            }
         } catch (Throwable th4) {
            if (0 == 0) {
               th2 = th4;
            } else if (null != th4) {
               th2.addSuppressed(th4);
            }
            throw th2;
         }
      } catch (Throwable th5) {
         if (0 == 0) {
            th = th5;
         } else if (null != th5) {
            th.addSuppressed(th5);
         }
         throw th;
      }
   }

   public static OpenSSHConfig parseFile(String file) throws Throwable {
      Throwable th = null;
      try {
         BufferedReader br = Files.newBufferedReader(Paths.get(Util.checkTilde(file), new String[0]), StandardCharsets.UTF_8);
         OpenSSHConfig openSSHConfig = new OpenSSHConfig(br);
         if (br != null) {
            br.close();
         }
         return openSSHConfig;
      } catch (Throwable th2) {
         if (0 == 0) {
            th = th2;
         } else if (null != th2) {
            th.addSuppressed(th2);
         }
         throw th;
      }
   }

   OpenSSHConfig(BufferedReader br) throws IOException {
      this.config = new Hashtable<>();
      this.hosts = new Vector<>();
      _parse(br);
   }

   private void _parse(BufferedReader br) throws IOException {
      String host = "";
      Vector<String[]> kv = (Vector)new Vector<>();
      String l = null;
      while ((l = br.readLine()) != null) {
         l = l.trim();
         if (l.length() == 0 || l.startsWith("#"))
            continue;
         String[] key_value = l.split("[= \t]", 2);
         for (int i = 0; i < key_value.length; i++)
            key_value[i] = key_value[i].trim();
         if (key_value.length <= 1)
            continue;
         if (key_value[0].equalsIgnoreCase("Host")) {
            this.config.put(host, kv);
            this.hosts.addElement(host);
            host = key_value[1];
            kv = (Vector)new Vector<>();
            continue;
         }
         kv.addElement(key_value);
      }
      this.config.put(host, kv);
      this.hosts.addElement(host);
   }

   public ConfigRepository.Config getConfig(String host) {
      return new MyConfig(host);
   }

   static Hashtable<String, String> getKeymap() {
      return keymap;
   }

   private static final Hashtable<String, String> keymap = new Hashtable<>();

   static {
      keymap.put("kex", "KexAlgorithms");
      keymap.put("server_host_key", "HostKeyAlgorithms");
      keymap.put("cipher.c2s", "Ciphers");
      keymap.put("cipher.s2c", "Ciphers");
      keymap.put("mac.c2s", "Macs");
      keymap.put("mac.s2c", "Macs");
      keymap.put("compression.s2c", "Compression");
      keymap.put("compression.c2s", "Compression");
      keymap.put("compression_level", "CompressionLevel");
      keymap.put("MaxAuthTries", "NumberOfPasswordPrompts");
   }

   class MyConfig implements ConfigRepository.Config {
      private String host;

      private Vector<Vector<String[]>> _configs = new Vector<>();

      MyConfig(String host) {
         this.host = host;
         this._configs.addElement((Vector<String[]>)OpenSSHConfig.this.config.get(""));
         byte[] _host = Util.str2byte(host);
         if (OpenSSHConfig.this.hosts.size() > 1)
            for (int i = 1; i < OpenSSHConfig.this.hosts.size(); i++) {
               boolean anyPositivePatternMatches = false;
               boolean anyNegativePatternMatches = false;
               String[] patterns = ((String)OpenSSHConfig.this.hosts.elementAt(i)).split("[ \t]");
               for (int j = 0; j < patterns.length; j++) {
                  boolean negate = false;
                  String foo = patterns[j].trim();
                  if (foo.startsWith("!")) {
                     negate = true;
                     foo = foo.substring(1).trim();
                  }
                  if (Util.glob(Util.str2byte(foo), _host))
                     if (negate) {
                        anyNegativePatternMatches = true;
                     } else {
                        anyPositivePatternMatches = true;
                     }
               }
               if (anyPositivePatternMatches && !anyNegativePatternMatches)
                  this._configs.addElement((Vector<String[]>)OpenSSHConfig.this.config.get(OpenSSHConfig.this.hosts.elementAt(i)));
            }
      }

      private String find(String key) {
         String originalKey = key;
         if (OpenSSHConfig.keymap.get(key) != null)
            key = (String)OpenSSHConfig.keymap.get(key);
         key = key.toUpperCase(Locale.ROOT);
         String value = null;
         for (int i = 0; i < this._configs.size(); i++) {
            Vector<String[]> v = this._configs.elementAt(i);
            for (int j = 0; j < v.size(); j++) {
               String[] kv = v.elementAt(j);
               if (kv[0].toUpperCase(Locale.ROOT).equals(key)) {
                  value = kv[1];
                  break;
               }
            }
            if (value != null)
               break;
         }
         if (OpenSSHConfig.keysWithListAdoption.contains(key) && value != null && (
                 value.startsWith("+") || value.startsWith("-") || value.startsWith("^"))) {
            String origConfig = Util.getConfig(originalKey).trim();
            if (value.startsWith("+")) {
               value = String.valueOf(origConfig) + "," + value.substring(1).trim();
            } else if (value.startsWith("-")) {
               List<String> algList =
                       (List<String>)Arrays.<String>stream(Util.split(origConfig, ",")).collect(Collectors.toList());
               byte b;
               int j;
               String[] arrayOfString;
               for (j = (arrayOfString = Util.split(value.substring(1).trim(), ",")).length, b = 0; b < j; ) {
                  String alg = arrayOfString[b];
                  algList.remove(alg.trim());
                  b++;
               }
               value = String.join(",", (Iterable)algList);
            } else if (value.startsWith("^")) {
               value = String.valueOf(value.substring(1).trim()) + "," + origConfig;
            }
         }
         return value;
      }

      private String[] multiFind(String key) {
         key = key.toUpperCase(Locale.ROOT);
         Vector<String> value = new Vector<>();
         for (int i = 0; i < this._configs.size(); i++) {
            Vector<String[]> v = this._configs.elementAt(i);
            for (int j = 0; j < v.size(); j++) {
               String[] kv = v.elementAt(j);
               if (kv[0].toUpperCase(Locale.ROOT).equals(key)) {
                  String foo = kv[1];
                  if (foo != null) {
                     value.remove(foo);
                     value.addElement(foo);
                  }
               }
            }
         }
         String[] result = new String[value.size()];
         value.toArray(result);
         return result;
      }

      public String getHostname() {
         return find("Hostname");
      }

      public String getUser() {
         return find("User");
      }

      public int getPort() {
         String foo = find("Port");
         int port = -1;
         try {
            port = Integer.parseInt(foo);
         } catch (NumberFormatException numberFormatException) {}
         return port;
      }

      public String getValue(String key) {
         if (key.equals("compression.s2c") || key.equals("compression.c2s")) {
            String foo = find(key);
            if (foo == null || foo.equals("no"))
               return "none,zlib@openssh.com,zlib";
            return "zlib@openssh.com,zlib,none";
         }
         return find(key);
      }

      public String[] getValues(String key) {
         return multiFind(key);
      }
   }
}
