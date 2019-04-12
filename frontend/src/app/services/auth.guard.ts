import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, CanActivate, Router, RouterStateSnapshot } from '@angular/router';

@Injectable()
export class AuthenticationGuard implements CanActivate {
    constructor(private router: Router) { }

    canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
        if (localStorage.getItem('apiToken') !== null) {
            return true;
        } else {
            this.router.navigate(['/']);
            return false;
        }
    }
}
