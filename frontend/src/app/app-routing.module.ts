import {NgModule} from '@angular/core';
import {RouterModule, Routes} from '@angular/router';
import {AuthComponent} from './auth/auth.component';
import {HomeComponent} from './home/home.component';
import {NotFoundComponent} from './not-found.component';

const appRoutes: Routes = [
  {
    path: '', redirectTo: 'auth', pathMatch: 'full'
  },
  {
    path: 'auth', component: AuthComponent
  },
  {
    path: 'home', component: HomeComponent
  },
  {path: 'not-found', component: NotFoundComponent},
  {path: '**', redirectTo: 'not-found'}
];

@NgModule({
  imports: [RouterModule.forRoot(appRoutes, {enableTracing: false})],
  exports: [RouterModule]
})
export class AppRoutingModule {
}
