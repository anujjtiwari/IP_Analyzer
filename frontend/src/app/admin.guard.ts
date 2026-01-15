import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { FormService } from './form.service';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Observable, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

@Injectable({
    providedIn: 'root'
})
export class AdminGuard implements CanActivate {

    constructor(private formService: FormService, private router: Router, private snackBar: MatSnackBar) { }

    canActivate(): Observable<boolean> {
        return this.formService.is_admin().pipe(
            map(response => {
                console.log(response);
                return true;
            }),
            catchError(error => {
                this.snackBar.open('You are not authorized to access this page!', 'Close', {
                    duration: 5000,
                    horizontalPosition: 'center',
                    verticalPosition: 'top',
                });
                this.router.navigate(['/home']);
                return of(false);
            })
        );
    }
}
