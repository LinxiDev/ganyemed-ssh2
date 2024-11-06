package ch.ethz.ssh2.jsch;

public interface ConfigRepository {
   ConfigRepository.Config defaultConfig = new ConfigRepository.Config() {
      public String getHostname() {
         return null;
      }

      public String getUser() {
         return null;
      }

      public int getPort() {
         return -1;
      }

      public String getValue(String key) {
         return null;
      }

      public String[] getValues(String key) {
         return null;
      }
   };
   ConfigRepository nullConfig = new ConfigRepository() {
      public ConfigRepository.Config getConfig(String host) {
         return defaultConfig;
      }
   };

   ConfigRepository.Config getConfig(String var1);

   public interface Config {
      String getHostname();

      String getUser();

      int getPort();

      String getValue(String var1);

      String[] getValues(String var1);
   }
}
