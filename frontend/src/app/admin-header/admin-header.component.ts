import { Component, OnInit } from '@angular/core';
import { AuthService } from '../auth.service';
import { FormService } from '../form.service';
import { Router } from '@angular/router';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { LoaderComponent } from '../loader/loader.component';
import { CommonModule } from '@angular/common';

@Component({
	selector: 'app-admin-header',
	standalone: true,
	imports: [MatSnackBarModule, LoaderComponent, CommonModule],
	templateUrl: './admin-header.component.html',
	styleUrl: './admin-header.component.css'
})
export class AdminHeaderComponent {
	adminName: string = "";
	isLoading = false;

	constructor(private router: Router, private authservice: AuthService,
		private formService: FormService, private snackBar: MatSnackBar,
	) { }

	ngOnInit(): void {
		this.formService.get_admin_name().subscribe({
			next: (response) => {
				this.adminName = JSON.parse(response)['admin_name'];
			},
			error: (error) => {
				this.snackBar.open('Unauthorized!', 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top'
				});

				this.router.navigate(['/home']);
			},
			complete: () => {
				console.log("User Name Handling Completed.")
			}
		});
	}

	navigateToProfile() {
		this.isLoading = true;
		this.router.navigate(['/profile']);
		this.isLoading = false;
	}

	logout() {
		// Handle logout logic here
		this.isLoading = true;
		this.authservice.logout();
		this.formService.user_sign_out().subscribe({
			next: (response) => {
				console.log(response);
				this.isLoading = false;
			},
			error: (error) => {
				this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});
				this.isLoading = false;
			},
			complete: () => {
				console.log('User Sign Out Handling Completed.');
			},
		})

		console.log('User logged out');
		this.router.navigate(['/sign-in']);
	}

	navigateToHome() {
		this.isLoading = true;
		this.router.navigate(['/home'])
		this.isLoading = false;
	}
}
