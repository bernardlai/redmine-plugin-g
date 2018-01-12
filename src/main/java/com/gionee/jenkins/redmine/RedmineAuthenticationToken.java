package com.gionee.jenkins.redmine;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.AbstractAuthenticationToken;


import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;

public class RedmineAuthenticationToken extends AbstractAuthenticationToken {
	/**
	 *
	 */
	private static final long serialVersionUID = 1L;
	//private final String accessToken;

	private final String userName;
	//private transient final GitlabAPI gitLabAPI;
	//private transient final GitlabUser me;
	private transient RedmineSecurityRealm myRealm = null;

	/**
	 * Cache for faster organization based security
	 */
	//private static final Cache<String, Set<String>> userOrganizationCache = CacheBuilder.newBuilder()
	//		.expireAfterWrite(1, TimeUnit.HOURS).build();

	//private static final Cache<String, Set<String>> repositoryCollaboratorsCache = CacheBuilder.newBuilder()
	//		.expireAfterWrite(1, TimeUnit.HOURS).build();

	//private static final Cache<String, Set<String>> repositoriesByUserCache = CacheBuilder.newBuilder()
	//		.expireAfterWrite(1, TimeUnit.HOURS).build();

	//private static final Cache<String, Boolean> publicRepositoryCache = CacheBuilder.newBuilder()
	//		.expireAfterWrite(1, TimeUnit.HOURS).build();

	//private static final Cache<String, List<GitlabProject>> groupRepositoriesCache = CacheBuilder.newBuilder()
	//		.expireAfterWrite(1, TimeUnit.HOURS).build();

	private final List<GrantedAuthority> authorities = new ArrayList<>();

	public RedmineAuthenticationToken(String name) throws IOException {
		super(new GrantedAuthority[] {});

		//this.accessToken = accessToken;
		//this.gitLabAPI = GitlabAPI.connect(gitlabServer, accessToken, tokenType);

		//this.me = gitLabAPI.getUser();
		//assert this.me != null;

		setAuthenticated(true);

		this.userName = name;
		authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
		Jenkins jenkins = Jenkins.getInstance();
		if (jenkins != null && jenkins.getSecurityRealm() instanceof RedmineSecurityRealm) {
			if (myRealm == null) {
				myRealm = (RedmineSecurityRealm) jenkins.getSecurityRealm();
			}
			// Search for scopes that allow fetching team membership. This is
			// documented online.
			// https://developer.gitlab.com/v3/orgs/#list-your-organizations
			// https://developer.gitlab.com/v3/orgs/teams/#list-user-teams
			//List<GitlabGroup> myTeams = gitLabAPI.getGroups();
			//for (GitlabGroup group : myTeams) {
			//	LOGGER.log(Level.FINE, "Fetch teams for user " + userName + " in organization " + group.getName());
			//	authorities.add(new GrantedAuthorityImpl(group.getName()));
			//	authorities.add(new GrantedAuthorityImpl(
			//			group + GitLabOAuthGroupDetails.ORG_TEAM_SEPARATOR + group.getName()));
			//}
		}
	}

	/**
	 * Gets the OAuth access token, so that it can be persisted and used
	 * elsewhere.
	 */
	//public String getAccessToken() {
	//	return accessToken;
	//}

	//public GitlabAPI getGitLabAPI() {
	//		return gitLabAPI;
	//}

	@Override
	public GrantedAuthority[] getAuthorities() {
		return authorities.toArray(new GrantedAuthority[authorities.size()]);
	}

	@Override
	public Object getCredentials() {
		return ""; // do not expose the credential
	}

	/**
	 * Returns the login name in GitLab.
	 */
	@Override
	public String getPrincipal() {
		return this.userName;
	}

	/**
	 * Returns the GHMyself object from this instance.
	 */
	//public GitlabUser getMyself() {
	//	return me;
	//}
}