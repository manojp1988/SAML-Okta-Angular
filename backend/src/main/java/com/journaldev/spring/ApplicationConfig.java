package com.journaldev.spring;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;


@EnableWebMvc
@Configuration
@PropertySource("classpath:application.properties")
@ComponentScan({ "com.journaldev.spring.*" })
public class ApplicationConfig {}