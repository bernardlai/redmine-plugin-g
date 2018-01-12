package com.gionee.jenkins.redmine;


import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;
import org.jfree.util.Log;


import hudson.Extension;
import hudson.model.Descriptor;


import com.gionee.jenkins.redmine.util.Constants;

import jenkins.security.SecurityListener;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import org.acegisecurity.GrantedAuthority;

import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.ParameterParser;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.message.BasicNameValuePair;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import hudson.model.User;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.ProxyConfiguration;
import jenkins.model.Jenkins;

/**
 * @author Yasuyuki Saito
 */
public class RedmineSecurityRealm extends SecurityRealm {

    /** Logger */
    private static final Logger LOGGER = Logger.getLogger(RedmineSecurityRealm.class.getName());

    private String redmineWebUri;
    private String redmineApiUri;
    private String clientID;
    private String clientSecret;

    /**
     * @param redmineWebUri
     *            The URI to the root of the web UI for Redmine .
     * @param redmineApiUri
     *            The URI to the root of the API for Redmine .
     * @param clientID
     *            The client ID for the created OAuth Application.
     * @param clientSecret
     *            The client secret for the created Redmine OAuth Application.
     */
    
    @DataBoundConstructor
    public RedmineSecurityRealm(String redmineWebUri, String redmineApiUri, String clientID,  String clientSecret) {

        this.redmineWebUri  = StringUtils.isBlank(redmineWebUri)     ? Constants.REDMINE_WEBURI       : redmineWebUri;
        this.redmineApiUri  = StringUtils.isBlank(redmineApiUri)     ? Constants.REDMINE_APIURI       : redmineApiUri;
        this.clientID       = StringUtils.isBlank(clientID)          ? Constants.CLIENT_ID            : clientID;
        this.clientSecret   = StringUtils.isBlank(clientSecret)      ? Constants.CLIENT_SECRET        : clientSecret;
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) throws IOException {
        // 2. Requesting authorization :
        
        List<NameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("redirect_uri", buildRedirectUrl(request, referer)));
        parameters.add(new BasicNameValuePair("response_type", "code"));
        parameters.add(new BasicNameValuePair("client_id", clientID));

        return new HttpRedirect(redmineWebUri + "/oauth/authorize?" + URLEncodedUtils.format(parameters, StandardCharsets.UTF_8));
    }

    private String buildRedirectUrl(StaplerRequest request, String referer) throws MalformedURLException {
        URL currentUrl = new URL(request.getRequestURL().toString());
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair("state", referer));

        URL redirect_uri = new URL(currentUrl.getProtocol(), currentUrl.getHost(), currentUrl.getPort(),
                request.getContextPath() + "/securityRealm/finishLogin?" + URLEncodedUtils.format(parameters, StandardCharsets.UTF_8));
        return redirect_uri.toString();
    }

    /**
     * This is where the user comes back to at the end of the OpenID redirect
     * ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        String code = request.getParameter("code");
        //LOGGER.info("laihh    doFinishLogin");
        if (StringUtils.isBlank(code)) {
            LOGGER.info("doFinishLogin: missing code or private_token.");
            return HttpResponses.redirectToContextRoot();
        }

        String state = request.getParameter("state");

        HttpPost httpPost = new HttpPost(redmineWebUri + "/oauth/token");
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair("client_id", clientID));
        parameters.add(new BasicNameValuePair("client_secret", clientSecret));
        parameters.add(new BasicNameValuePair("code", code));
        parameters.add(new BasicNameValuePair("grant_type", "authorization_code"));
        parameters.add(new BasicNameValuePair("redirect_uri", buildRedirectUrl(request, state)));
        httpPost.setEntity(new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8));

        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpHost proxy = getProxy(httpPost);
        if (proxy != null) {
            RequestConfig config = RequestConfig.custom()
                    .setProxy(proxy)
                    .build();
            httpPost.setConfig(config);
        }

        org.apache.http.HttpResponse response = httpclient.execute(httpPost);

        HttpEntity entity = response.getEntity();

        String content = EntityUtils.toString(entity);

        // When HttpClient instance is no longer needed,
        // shut down the connection manager to ensure
        // immediate deallocation of all system resources
        httpclient.close();

        String name = extract(content ,"name");

        if (StringUtils.isNotBlank(name)) {

            // only set the access token if it exists.
            RedmineAuthenticationToken auth = new RedmineAuthenticationToken(name);
            SecurityContextHolder.getContext().setAuthentication(auth);

            //GitlabUser self = auth.getMyself();
            User user = User.current();
            if (user != null) {
                user.setFullName(extract(content ,"username"));
                //LOGGER.info(user.getApi());
                //user.setApiToken(extract(content ,"access_token"));
                // Set email from gitlab only if empty
            //    if (!user.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {
            //        user.addProperty(new Mailer.UserProperty(auth.getMyself().getEmail()));
            //    }
            } 
            //SecurityListener.fireAuthenticated(new GitLabOAuthUserDetails(self, auth.getAuthorities()));
        } else {
            LOGGER.info("Redmine did not return an access token.");
        }

        if (StringUtils.isNotBlank(state)) {
            return HttpResponses.redirectTo(state);
        }
        return HttpResponses.redirectToContextRoot();
    }

    /**
     * Returns the proxy to be used when connecting to the given URI.
     */
    private HttpHost getProxy(HttpUriRequest method) throws URIException {
        Jenkins jenkins = Jenkins.getInstance();
        ProxyConfiguration proxy = jenkins.proxy;
        if (proxy == null) {
            return null; // defensive check
        }

        Proxy p = proxy.createProxy(method.getURI().getHost());
        switch (p.type()) {
            case DIRECT:
                return null; // no proxy
            case HTTP:
                InetSocketAddress sa = (InetSocketAddress) p.address();
                return new HttpHost(sa.getHostName(), sa.getPort());
            case SOCKS:
            default:
                return null; // not supported yet
        }
    }

    private String extract(String content, String key) {

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonTree = mapper.readTree(content);
            JsonNode node = jsonTree.get(key);
            if (node != null) {
                return node.asText();
            }
        } catch (IOException e) {
            Log.error(e.getMessage(), e);
        }
        return null;
    }

    /*
     * (non-Javadoc)
     *
     * @see hudson.security.SecurityRealm#allowsSignup()
     */
    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {

            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof RedmineAuthenticationToken) {
                    return authentication;
                }
                if (authentication instanceof UsernamePasswordAuthenticationToken) {
                    try {
                        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
                        String username = "";
                        
                        if ( clientSecret.equals( token.getCredentials().toString() ) ) {
                            username = token.getPrincipal().toString();
                        } 
                        RedmineAuthenticationToken redmine = new RedmineAuthenticationToken(username);
                        SecurityContextHolder.getContext().setAuthentication(redmine);
                        return redmine;
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                throw new BadCredentialsException("Unexpected authentication type: " + authentication);
            }
        }, new UserDetailsService() {
            @Override

            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
                return RedmineSecurityRealm.this.loadUserByUsername(username);
            }
        });
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        // if we just redirect to the root and anonymous does not have Overall read then we will start a login all over again.
        // we are actually anonymous here as the security context has been cleared
        Jenkins jenkins = Jenkins.getInstance();
        assert jenkins != null;
        if (jenkins.hasPermission(Jenkins.READ)) {
            return super.getPostLogOutUrl(req, auth);
        }
        return req.getContextPath() + "/" + RedmineLogoutAction.POST_LOGOUT_URL;
    }

    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getHelpFile() {
            return "/plugin/gionee/help-auth-overview.html";
        }
        @Override
        public String getDisplayName() {
            return "Redmine User Auth";
        }
    }

    @Extension
    public static DescriptorImpl install() {
        return new DescriptorImpl();
    }

    

    


    /**
     *
     * @return
     */
    public String getRedmineWebUri() {
        return redmineWebUri;
    }

    /**
     *
     * @return
     */
    public String getRedmineApiUri() {
        return redmineApiUri;
    }

    /**
     *
     * @return
     */
    public String getClientID() {
        return clientID;
    }

    /**
     *
     * @return
     */
    public String getClientSecret() {
        return clientSecret;
    }

    
}
