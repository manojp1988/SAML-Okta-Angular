import { Component, OnInit } from '@angular/core';
import { AuthenticationService } from '../services/auth.service';
import { Observable } from 'rxjs';
import { Router } from '@angular/router';

@Component({
    selector: 'app-home',
    templateUrl: './home.component.html'
})
export class HomeComponent implements OnInit {
    apiResult$: Observable<any>;

    constructor(private service: AuthenticationService, private router: Router) { }

    ngOnInit() {

        if (localStorage.getItem('apiToken') === null) {
            this.service.getToken().subscribe(apiToken => {
                localStorage.setItem('apiToken', apiToken.token);
                this.apiResult$ = this.service.callApi();
            });
        } else {
            this.apiResult$ = this.service.callApi();
        }
    }

    logout() {
        this.service.logout();

        if (this.service.isLogoutSuccess()) {
            this.router.navigate(['/']);
        }
    }
}
