package com.gionee.jenkins.redmine;

/**
 *
 * @author Yasuyuki Saito
 */
public class RedmineUserData {

    /** */
    private String username;

    /** */
    private String password;

    /** */
    private String salt;
    
    /**laihh */
    private String apitoken;

    /**
     *
     * @return
     */
    public String getUsername() {
        return username;
    }

    /**
     *
     * @param username
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     *
     * @return
     */
    public String getPassword() {
        return password;
    }

    /**
     *
     * @param password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     *
     * @return
     */
    public String getSalt() {
        return salt;
    }

    /**
     *
     * @param salt
     */
    public void setSalt(String salt) {
        this.salt = salt;
    }
    /**
    * laihh
    * @return
    */
   public String getApitoken() {
       return apitoken;
   }

    /**
    *laihh
    * @param apitoken
    */
   public void setApitoken(String apitoken) {
       this.apitoken = apitoken;
   }
}
