package com.journaldev.spring.dto;


import java.io.Serializable;

public class ApiToken implements Serializable {

    private String token;

    public ApiToken(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

	@Override
	public String toString() {
		return "ApiToken [token=" + token + "]";
	}
    
    
}
