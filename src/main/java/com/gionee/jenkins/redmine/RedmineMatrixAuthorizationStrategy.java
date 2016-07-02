/*
 * The MIT License
 * 
 * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.gionee.jenkins.redmine;

import com.gionee.jenkins.redmine.util.Constants;

import hudson.model.Descriptor;
import hudson.Extension;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionGroup;
import hudson.security.SidACL;
import hudson.security.SparseACL;
import jenkins.model.Jenkins;
import hudson.model.Job;
import hudson.model.Item;
import net.sf.json.JSONObject;


import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.DataBoundConstructor;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.GrantedAuthoritySid;
import org.acegisecurity.acls.sid.Sid;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Collections;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.BufferedReader;

import org.apache.commons.lang.StringUtils;


/**
 * Role-based authorization via a matrix.
 *
 * @author Kohsuke Kawaguchi
 */
// TODO: think about the concurrency commitment of this class
public class RedmineMatrixAuthorizationStrategy extends AuthorizationStrategy {
    //private transient SidACL acl = new AclImpl();
    //private final Map<Permission,Set<String>> grantedPermissions = new HashMap<Permission, Set<String>>();
    //private String grantedPermissions = new String();
    /** Redmine DBMS */
    private final String url ;

    
    //private SparseACL authenticated = new SparseACL(null);
    private static final SparseACL ANONYMOUS_READ = new SparseACL(null);
    
    static {
        //ANONYMOUS_READ.add(ACL.EVERYONE, Jenkins.ADMINISTER,false);
        ANONYMOUS_READ.add(ACL.ANONYMOUS, Jenkins.ADMINISTER,false);
        ANONYMOUS_READ.add(ACL.ANONYMOUS, Permission.READ,false);
    }
    
    @DataBoundConstructor
    public RedmineMatrixAuthorizationStrategy(String url) {
        this.url = StringUtils.isBlank(url)         ? Constants.REDMINEURL              : url;
        
    }
    
    
    @Override
    public ACL getRootACL() {
        String stringsid = getSid(Jenkins.getAuthentication());
        if ( stringsid == null || stringsid.isEmpty() || stringsid.equals("anonymous") || stringsid.equals("role_everyone")) {
            return ANONYMOUS_READ;
        } else {
            SparseACL acl = new SparseACL(null);
            Sid sid = new PrincipalSid(stringsid);
            //acl.add(sid,Jenkins.ADMINISTER,true);
            //LOGGER.info(stringsid);
            String params = new String();
            JSONObject jsStr = new JSONObject();
            try {
                params = getJsonStringPermission(stringsid);
            } catch (Exception e) {
                params = null;
                throw new RedmineAuthenticationException("RedmineSecurity: Sid Error", e);
            }

            if (params == null || params.isEmpty()) {
                return ANONYMOUS_READ;
            } else {
               jsStr = JSONObject.fromObject(params);

               JSONObject permissions = jsStr.getJSONObject("permissions");
               if ( permissions.toString() == null || permissions.toString().isEmpty()) {
                   return ANONYMOUS_READ; 
               } else {
                  if (permissions.containsKey("admin") && permissions.get("admin").toString().equals("true")){
                      //LOGGER.info("admin");
                      acl.add(sid,Jenkins.ADMINISTER,true);
                      return acl;  
                  }
                  else {
                     if (permissions.containsKey("view_jenkins_jobs")) {
                      List<String> jobs = (List<String>) permissions.get("view_jenkins_jobs");
                           if (jobs ==null||jobs.isEmpty()) {

                           } else {
                               acl.add(sid,Jenkins.READ,true);
                               acl.add(sid,Job.READ,true);
                               LOGGER.info("view_jenkins_jobs");
                               //return true;
                           } 
                        }
                     if (permissions.containsKey("build_jenkins_jobs")) {
                      //LOGGER.info("admin");
                      //LOGGER.info(permissions.get("build_jenkins_jobs").toString());
                      List<String> jobs = (List<String>) permissions.get("build_jenkins_jobs");
                           if (jobs ==null||jobs.isEmpty()) {

                           } else {
                               acl.add(sid,Jenkins.READ,true);
                               acl.add(sid,Job.BUILD,true);
                               acl.add(sid,Job.CANCEL,true);
                               LOGGER.info("build_jenkins_jobs");
                               //return true;
                           }
                  }
                   if (permissions.containsKey("edit_jenkins_settings")) {
                      //LOGGER.info(permissions.get("edit_jenkins_settings").toString());
                      List<String> jobs = (List<String>) permissions.get("edit_jenkins_settings");
                           if (jobs ==null||jobs.isEmpty()) {

                           } else {
                               acl.add(sid,Jenkins.READ,true);
                               acl.add(sid,Job.CONFIGURE,true);
                               LOGGER.info("edit_jenkins_settings");
                               //return true;
                           }
                  }
                   if  (permissions.containsKey("view_build_activity")) {
                      //LOGGER.info(permissions.get("view_build_activity").toString());
                      List<String> jobs = (List<String>) permissions.get("view_build_activity");
                           if (jobs ==null||jobs.isEmpty()) {

                           } else {
                               acl.add(sid,Jenkins.READ,true);
                               acl.add(sid,Job.WORKSPACE,true);
                               LOGGER.info("view_build_activity");
                               //return true;
                           }
                  }
                  } 
                      
               }
            }
            return acl;
        }
    }

    public Set<String> getGroups() {
        return Collections.emptySet();
    }
    

    
    protected String getSid(Authentication p) {
        if (p.getPrincipal() instanceof RedmineUserDetails)
            return ((RedmineUserDetails) p.getPrincipal()).getUsername();
        if (p instanceof GrantedAuthoritySid)
            return ((GrantedAuthoritySid) p).getGrantedAuthority();
        if (p instanceof PrincipalSid)
            return ((PrincipalSid) p).getPrincipal();
        //if (p == EVERYONE)
        //    return "role_everyone";
        // hmm...
        return p.getPrincipal().toString();
    }
    
    public String getJsonStringPermission(String sid) throws Exception {  
        String urlstring = new String();
        urlstring = getUrl()+"/jenkins/permissions.json?login="+sid;
        URL url = new URL(urlstring);
        
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();  
        connection.setRequestMethod("PUT");
        connection.setRequestProperty("Content-Type", "application/json"); 
        connection.connect(); 

        InputStream inputStream = connection.getInputStream();  
        //对应的字符编码转换  
        Reader reader = new InputStreamReader(inputStream, "UTF-8");  
        BufferedReader bufferedReader = new BufferedReader(reader);  
        String str = null;  
        StringBuffer sb = new StringBuffer();  
        while ((str = bufferedReader.readLine()) != null) {  
            sb.append(str);  
        }
        connection.disconnect();
        return sb.toString();
    }  
    
    
    @Extension
    public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

    public static class DescriptorImpl extends Descriptor<AuthorizationStrategy> {
        protected DescriptorImpl(Class<? extends RedmineMatrixAuthorizationStrategy> clazz) {
            super(clazz);
        }

        public DescriptorImpl() {
        }
        
        public String getHelpFile() {
            return "/plugin/gionee/help-Perm-overview.html";
        }
        
        
        public String getDisplayName() {
            return "Redmine User Permission";
        }

        @Override
        public AuthorizationStrategy newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            //String url = new String();
            //LOGGER.info(req.toString());
            String url = formData.get("url").toString();
             LOGGER.info(url);
            //url = RedmineMatrixAuthorizationStrategy.this.getUrl();
            RedmineMatrixAuthorizationStrategy gmas = create(url);
            //gmas.url = "http://127.0.0.1/redmine";
            return gmas;
        }

        protected RedmineMatrixAuthorizationStrategy create(String url) {
            return new RedmineMatrixAuthorizationStrategy(url);
        }
    }
    
    /**
     *
     * @return
     */
    public String getUrl() {
        return url;
    }
    private static final Logger LOGGER = Logger.getLogger(RedmineMatrixAuthorizationStrategy.class.getName());
}

