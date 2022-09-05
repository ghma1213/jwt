package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// 필터는 스프링 시큐리티 필터가 진행한 후에 진행된다.
// 스프링 시큐리티보다 먼저 실행되게 하려면 application.yml에 spring.security.filter.order=갯수
// 갯수만큼 시큐리티 필터 앞에 필터를 넣어줄 수 있다.
@Configuration
public class FilterConfig {
//    @Bean
//    public FilterRegistrationBean<MyFilter1> filter1() {
//        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
//        bean.addUrlPatterns("/*");
//        bean.setOrder(0); // 낮은 번호가 필터 중에서 가장 먼저 실행된다.
//        return bean;
//    }

//    @Bean
//    public FilterRegistrationBean<MyFilter2> filter2() {
//        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
//        bean.addUrlPatterns("/*");
//        bean.setOrder(1); // 낮은 번호가 필터 중에서 가장 먼저 실행된다.
//        return bean;
//    }
}
