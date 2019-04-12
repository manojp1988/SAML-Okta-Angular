import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ApiToken } from '../model/api-token';
import { Credentials } from '../model/credentials';
import { Router } from '@angular/router';

@Injectable()
export class AuthenticationService {
  readonly serverUrl = 'https://dev.spectrags.com/backend';
  logoutSuccess = false;

  constructor(private httpClient: HttpClient, private router: Router) {}

  isLogoutSuccess(): boolean {
    return this.logoutSuccess;
  }

  getToken(): Observable<ApiToken> {
      return this.httpClient.get<ApiToken>(`${this.serverUrl}/auth/token`);
  }

  formLogin(credentials: Credentials): Observable<ApiToken> {
    return this.httpClient.post<ApiToken>(`${this.serverUrl}/auth/formLogin`, credentials);
  }

  login() {
    setTimeout(() => window.location.replace(`${this.serverUrl}/saml/login`), 4000);
  }

  logout() {
    localStorage.removeItem('apiToken');
    this.router.navigate(['/']);
    this.logoutSuccess = true;

    this.httpClient.get(`${this.serverUrl}/saml/logout`).subscribe();
  }

  callApi() {
    const apiToken = localStorage.getItem('apiToken');
    return this.httpClient.get(`${this.serverUrl}/api/mycontroller/`, {
      headers: {
        'x-auth-token': apiToken
      }
    });
  }
}
