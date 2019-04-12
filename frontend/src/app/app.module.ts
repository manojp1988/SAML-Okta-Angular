import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';
import { HomeComponent } from './home/home.component';
import { AppRoutingModule } from './app-routing.module';
import { RouterModule } from '@angular/router';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { AuthComponent } from './auth/auth.component';
import {NotFoundComponent} from './not-found.component';
import {AuthenticationService} from './services/auth.service';
import {AuthenticationGuard} from './services/auth.guard';

@NgModule({
  declarations: [AppComponent, HomeComponent, AuthComponent, NotFoundComponent],
  imports: [
    BrowserModule,
    ReactiveFormsModule,
    HttpClientModule,
    AppRoutingModule,
    RouterModule
  ],
  providers: [AuthenticationService, AuthenticationGuard],
  bootstrap: [AppComponent]
})
export class AppModule {}
