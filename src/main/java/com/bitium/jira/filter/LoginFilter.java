package com.bitium.jira.filter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.atlassian.sal.api.auth.LoginUriProvider;
import com.bitium.jira.config.SAMLJiraConfig;
import com.bitium.jira.util.URLValidator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class LoginFilter implements Filter {

    private SAMLJiraConfig config;
    private LoginUriProvider loginUriProvider;
    private static final Log LOGGER = LogFactory.getLog(LoginFilter.class);
    private final SecureRandom secureRand = new SecureRandom();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        boolean idpRequired = config.getIdpRequiredFlag();
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;

        try {

            String uri = URLValidator.getSanitizedUrl(req.getRequestURI());

            if(uri != null) {
                if (idpRequired) {
                    res.sendRedirect(res.encodeRedirectURL(loginUriProvider.getLoginUri(new URI(uri)).toString() + "&samlerror=general?r=" + secureRand.nextLong()));
                } else {
                    chain.doFilter(req, res);
                }
            }
        } catch (URISyntaxException e) {
            LOGGER.error(e);
        }
    }

    @Override
    public void destroy() {
        throw new UnsupportedOperationException();
    }

    public void setConfig(SAMLJiraConfig config) {
        this.config = config;
    }

    public void setLoginUriProvider(LoginUriProvider loginUriProvider) {
        this.loginUriProvider = loginUriProvider;
    }

}
