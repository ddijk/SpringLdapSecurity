package hello;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;

@Configuration
@ConfigurationProperties(prefix = "security.ldap")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    String passwordAttribute = "userPassword";
    String managerPassword = "admin";
    String managerDn = "cn=admin,dc=example,dc=org";
    String userDnPattern = "uid={0},ou=people";

    String url;

    boolean useAnonymousBind = true;

    public void setPasswordAttribute(String passwordAttribute) {
        this.passwordAttribute = passwordAttribute;
    }

    public void setManagerPassword(String managerPassword) {
        this.managerPassword = managerPassword;
    }

    public void setManagerDn(String managerDn) {
        this.managerDn = managerDn;
    }

    public void setUserDnPattern(String userDnPattern) {
        this.userDnPattern = userDnPattern;
    }

    public void setUseAnonymousBind(boolean useAnonymousBind) {
        this.useAnonymousBind = useAnonymousBind;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().fullyAuthenticated()
                .and()
                .formLogin();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        System.out.println("url = " + url);
        System.out.println("useAnonymousBind = " + useAnonymousBind);
        if (useAnonymousBind) {
            auth
                    .ldapAuthentication()
                    .userDnPatterns(userDnPattern)
                    .contextSource()
                    .url(url)
                    .and()
                    .passwordCompare()
                    .passwordEncoder(new LdapShaPasswordEncoder())
                    .passwordAttribute(passwordAttribute);


        } else {

            auth
                    .ldapAuthentication()
                    .userDnPatterns(userDnPattern)
                    .contextSource()
                    .managerDn(managerDn)
                    .managerPassword(managerPassword)
                    .url(url)
                    .and()
                    .passwordCompare()
                    .passwordEncoder(new LdapShaPasswordEncoder())
                    .passwordAttribute(passwordAttribute);
        }
    }


    public void setUrl(String url) {
        this.url = url;
    }
}
