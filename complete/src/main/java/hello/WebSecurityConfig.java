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

    String url;

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
        auth
                .ldapAuthentication()
                .userDnPatterns("uid={0},ou=people")
//                .groupSearchBase("ou=groups")
                .contextSource()
//                .root("dc=tudelft,dc=example,dc=org")
                .managerDn("cn=admin,dc=example,dc=org")
                .managerPassword("admin")
                .url(url)
                .and()
                .passwordCompare()
                .passwordEncoder(new LdapShaPasswordEncoder())
                .passwordAttribute("userPassword");
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
