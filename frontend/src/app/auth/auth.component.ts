import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, Validators } from '@angular/forms';
import { AuthenticationService } from '../services/auth.service';
import { Router } from '@angular/router';
import { ApiToken } from '../model/api-token';

@Component({
  selector: 'app-auth',
  templateUrl: './auth.component.html'
})
export class AuthComponent implements OnInit {
  loginForm: FormGroup;
  apiToken: string;

  constructor(private service: AuthenticationService, private router: Router) {}

  ngOnInit() {
    this.loginForm = new FormGroup({
      username: new FormControl('', Validators.required),
      password: new FormControl('', Validators.required)
    });
  }

  formLogin() {
    this.service
      .formLogin(this.loginForm.value)
      .subscribe(r => this.handleTokenSuccess(r as ApiToken), err => console.error(err));
  }

  loginWithOkta() {
    this.service.login();
  }

  handleTokenSuccess(apiToken: ApiToken) {
    this.apiToken = apiToken.token;
    localStorage.setItem('apiToken', apiToken.token);
    this.router.navigate(['/home']);
  }
}
