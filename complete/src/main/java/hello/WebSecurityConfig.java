package hello;

import com.stucomm.api.authentication.AuthenticationRequest;
import com.stucomm.api.authentication.AuthenticationResponse;
import com.stucomm.api.plugin.PluginConfig;
import com.stucomm.api.plugin.PluginConfigurationException;
import com.stucomm.plugins.authentication.ldap.LdapSecurityProvider;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
            final MyUserDetailsService userDetailsService = createUserDetailsService();
            auth
//                    .authenticationProvider(new MyAuthenticationProvider())
                    .userDetailsService(userDetailsService)
                    .passwordEncoder(new MyPasswordEncoder(userDetailsService));
//                    .ldapAuthentication()
//                    .userDnPatterns(userDnPattern)
//                    .contextSource()
//                    .url(url)
//                    .and()
//                    .passwordCompare()
//                    .passwordEncoder(new LdapShaPasswordEncoder())
//                    .passwordAttribute(passwordAttribute);


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

    private MyUserDetailsService createUserDetailsService() {

        return new MyUserDetailsService();

//        return new UserDetailsService() {
//
//            @Override
//            public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
//                return new LdapUserDetails() {
//                    @Override
//                    public String getDn() {
//                        return "my dn";
//                    }
//
//                    @Override
//                    public void eraseCredentials() {
//
//                    }
//
//                    @Override
//                    public Collection<? extends GrantedAuthority> getAuthorities() {
//                        return Collections.emptyList();
//                    }
//
//                    @Override
//                    public String getPassword() {
//                        return "pw";
//                    }
//
//                    @Override
//                    public String getUsername() {
//                        return "bram";
//                    }
//
//                    @Override
//                    public boolean isAccountNonExpired() {
//                        return true;
//                    }
//
//                    @Override
//                    public boolean isAccountNonLocked() {
//                        return true;
//                    }
//
//                    @Override
//                    public boolean isCredentialsNonExpired() {
//                        return false;
//                    }
//
//                    @Override
//                    public boolean isEnabled() {
//                        return true;
//                    }
//                };
//            }
//        };
    }


    public void setUrl(String url) {
        this.url = url;
    }
}

//class MyAuthenticationProvider implements AuthenticationProvider {
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//
//        LdapSecurityProvider ldapSecurityProvider = new LdapSecurityProvider();
//
//        System.out.println("Authenticing....");
//        try {
//            ldapSecurityProvider.initialize(getPluginConfig());
//            AuthenticationRequest authRequest = AuthenticationRequest.builder()
//                    .username("student.bk@student.hku.nl")
//                    .password("bk1Geheim").build();
//            ldapSecurityProvider.login(authRequest);
//        } catch (PluginConfigurationException | com.stucomm.api.authentication.AuthenticationException e) {
//            System.out.println("Init failed. ");
//            throw new RuntimeException("blah:" + e.getMessage());
//        }
//        return new MyAuthentication();
//    }
//
//
//    @Override
//    public boolean supports(Class<?> aClass) {
//        System.out.println("***** supports");
//        return false;
//    }
//}

//class MyAuthentication implements Authentication {
//
//    @Override
//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        return Collections.emptyList();
//    }
//
//    @Override
//    public Object getCredentials() {
//        return "xxx";
//    }
//
//    @Override
//    public Object getDetails() {
//        return "yyy";
//    }
//
//    @Override
//    public Object getPrincipal() {
//        return "bram";
//    }
//
//    @Override
//    public boolean isAuthenticated() {
//        return true;
//    }
//
//    @Override
//    public void setAuthenticated(boolean b) throws IllegalArgumentException {
//
//    }
//
//    @Override
//    public String getName() {
//        return null;
//    }
//}

class MyPluginConfig implements PluginConfig {


    Map<String, String> configProps = new HashMap<>();

    public MyPluginConfig() {

//        configProps.put("java.naming.provider.url", "ldap://ldap.hku.nl");
        configProps.put("java.naming.provider.url", "ldap://localhost:9000");
        configProps.put("java.naming.security.authentication ", "simple");
        configProps.put("LDAP_USER_FILTER", "(&(objectClass=posixAccount)(mail=%s))");
        configProps.put("LDAP_SEARCH_BASE_DN", "dc=hku,dc=nl");
        configProps.put("ATTRIBUTE_STUDENT_NUMBER", "nlHkuID");
        configProps.put("TEST_STUDENT_NAME", "aa");
        configProps.put("TEST_STUDENT_PASSWORD", "bb");

    }

    @Override
    public String getValue(String s) {
        return configProps.get(s);
    }
}

class MyUserDetailsService implements UserDetailsService {

    private String username;

    public MyUserDetailsService() {
        System.out.println("constr. MyUserDetailService");
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        System.out.println("load by username for " + s);
        username = s;

        MyUserDetails userDetails = new MyUserDetails(s);

        return userDetails;
    }

    public String getUsername() {
        return username;
    }
}

class MyUserDetails implements UserDetails {

    private String username;

    public MyUserDetails(String username) {
        this.username = username;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        System.out.println("a");
        return Collections.emptyList();
    }

    @Override
    public String getPassword() {
        System.out.println("a2:" + username);
        return null;
    }

    @Override
    public String getUsername() {
        System.out.println("a3");
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        System.out.println("a4");
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        System.out.println("a5");
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        System.out.println("a6");
        return true;
    }

    @Override
    public boolean isEnabled() {
        System.out.println("enabled? a7");
        return true;
    }
}

class MyPasswordEncoder implements PasswordEncoder {


    private MyUserDetailsService userDetailsService;

    public MyPasswordEncoder(MyUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;

        System.out.println("user in MyPasswordEncoder: " + userDetailsService.getUsername());
    }

    @Override
    public String encode(CharSequence charSequence) {
        System.out.println("encode:" + charSequence.toString());

        return charSequence.toString();
    }

    @Override
    public boolean matches(CharSequence charSequence, String notUsed) {

        LdapSecurityProvider ldapSecurityProvider = new LdapSecurityProvider();

        System.out.println("Authenticating...."+userDetailsService.getUsername());
        try {
            ldapSecurityProvider.initialize(getPluginConfig());
            AuthenticationRequest authRequest = AuthenticationRequest.builder()
                    .username(userDetailsService.getUsername())
                    .password(charSequence.toString()).build();
            AuthenticationResponse resp = ldapSecurityProvider.login(authRequest);
            System.out.println("Auth resp:" + resp);
            return true;
        } catch (PluginConfigurationException | com.stucomm.api.authentication.AuthenticationException e) {
            System.out.println("Auth failed. ");
            throw new RuntimeException("blah:" + e.getMessage());
        }
    }

    private PluginConfig getPluginConfig() {
        return new MyPluginConfig();
    }

}