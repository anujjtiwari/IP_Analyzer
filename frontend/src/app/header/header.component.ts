import { Component, OnInit } from '@angular/core';
import { AuthService } from '../auth.service';
import { FormService } from '../form.service';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-header',
	standalone: true,
	imports: [CommonModule, LoaderComponent],
	templateUrl: './header.component.html',
	styleUrl: './header.component.css'
})
export class HeaderComponent implements OnInit {
	isLoading = false;
	userName: string = "";

	constructor(private router: Router, private authservice: AuthService,
		private formService: FormService,
	) { }

	ngOnInit(): void {
		this.formService.get_user_name().subscribe({
			next: (response) => {
				this.userName = JSON.parse(response)['user_name'];
			},
			error: (error) => {
				this.router.navigate(['/sign-in']);
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
			},
			error: (error) => {
				console.log(`Error: ${JSON.parse(error['error'])['message']}.`);
				// this.errorMessage = 'Invalid email or password';
			},
			complete: () => {
				console.log('User Sign Out Handling Completed.');
			},
		})

		console.log('User logged out');
		this.router.navigate(['/sign-in']);
		this.isLoading = false;
	}

	navigateToAdmin() {
		this.isLoading = true;
		this.router.navigate(['/admin'])
		this.isLoading = false;
	}

}
