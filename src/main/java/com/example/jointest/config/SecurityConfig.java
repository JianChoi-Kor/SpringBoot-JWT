package com.example.jointest.config;

import com.example.jointest.filter.JwtFilter;
import com.example.jointest.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;


    // 사용되는 곳이 없다? 뭐하는 용도인지 파악 필요
    /*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }
    */

    @Override
    public void configure(WebSecurity web) throws Exception{
        web.ignoring().antMatchers("/css/**", "/js/**", "/img/**", "/lib/*8");
        // static 디렉토리의 하위 파일 목록은 인증 무시 (통과)
    }

    // 암호화에 필요한 PasswordEncoder Bean 등록
    @Bean
    public PasswordEncoder passwordEncoder() {

        // return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }


    // authenticationManager Bean 등록
    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 필터 등록
        http
                .httpBasic().disable() // REST API만 고려, 기본 설정을 해제
                .csrf().disable() // csrf 사용 X
                .authorizeRequests().antMatchers("/authenticate")
                // 요청에 대한 사용 권한 체크
                .permitAll().anyRequest().authenticated()
                // 나머지 요청은 누구나 접근 가능
                .and().exceptionHandling().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                // 토큰 기반 인증이므로 세션도 사용 X
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        // jwtFilter는 UsernamePasswordAuthenticationFilter 전에 들어간다.

    }



}

