import { Routes } from '@angular/router';
import { SignInComponent } from './sign-in/sign-in.component';
import { SignUpComponent } from './sign-up/sign-up.component';
import { OtpPageComponent } from './otp-page/otp-page.component';
import { HomeComponent } from './home/home.component';
import { AuthGuard } from './auth.guard';
import { ResultsComponent } from './results/results.component';
import { AdminComponent } from './admin/admin.component';
import { ForgotPasswordComponent } from './forgot-password/forgot-password.component';
import { SetPasswordComponent } from './set-password/set-password.component';
import { SetPasswordGuard } from './set-password.guard';
import { AdminGuard } from './admin.guard';
import { ProfileComponent } from './profile/profile.component';
import { UpdatePasswordComponent } from './update-password/update-password.component';

export const routes: Routes = [
    { path: 'sign-in', component: SignInComponent },
    { path: 'sign-up', component: SignUpComponent },
    { path: 'forgot-password', component: ForgotPasswordComponent },
    { path: 'set-password', component: SetPasswordComponent, canActivate: [SetPasswordGuard] },
    { path: 'home', component: HomeComponent, canActivate: [AuthGuard] },
    { path: 'profile', component: ProfileComponent, canActivate: [AuthGuard] },
    { path: 'update-password', component: UpdatePasswordComponent, canActivate: [AuthGuard] },
    { path: 'results', component: ResultsComponent, canActivate: [AuthGuard] },
    { path: 'admin', component: AdminComponent, canActivate: [AdminGuard] },
    { path: 'otp-page/:target', component: OtpPageComponent },
    { path: '', redirectTo: '/sign-in', pathMatch: 'full' }, // Default route
    { path: '**', redirectTo: '/sign-in' } // Wildcard route for 404
];
