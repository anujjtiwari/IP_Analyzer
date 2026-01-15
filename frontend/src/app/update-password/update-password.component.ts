import { FormService } from './../form.service';
import { Component } from '@angular/core';
import {
	ReactiveFormsModule,
	FormGroup,
	FormControl,
	Validators,
	FormBuilder,
} from '@angular/forms';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { FaIconLibrary } from '@fortawesome/angular-fontawesome';
import {
	faEye as fasEye,
	faEyeSlash as fasEyeSlash,
} from '@fortawesome/free-solid-svg-icons';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-update-password',
	standalone: true,
	imports: [ReactiveFormsModule, CommonModule, FontAwesomeModule, RouterModule, MatSnackBarModule, LoaderComponent],
	templateUrl: './update-password.component.html',
	styleUrl: './update-password.component.css',
})
export class UpdatePasswordComponent {
	passwordUpdateForm!: FormGroup;
	isOldPasswordVisible = false;
	isNewPasswordVisible = false;
	isLoading = false;

	constructor(
		private fb: FormBuilder,
		library: FaIconLibrary,
		private formService: FormService,
		private router: Router,
		private snackBar: MatSnackBar,
	) {
		library.addIcons(fasEye, fasEyeSlash);
	}

	ngOnInit(): void {
		this.passwordUpdateForm = this.fb.group({
			oldPassword: new FormControl('', [Validators.required]),
			newPassword: new FormControl('', [Validators.required]),
		});
	}

	get oldPassword() {
		return this.passwordUpdateForm.get('oldPassword');
	}

	get newPassword() {
		return this.passwordUpdateForm.get('newPassword');
	}

	onSubmit(): void {
		this.isLoading = true;
		if (this.passwordUpdateForm.valid) {
			this.formService.update_password(this.passwordUpdateForm.value).subscribe({
				next: (response) => {
					this.snackBar.open(JSON.parse(response)['message'], 'Close', {
						duration: 5000, // Snackbar will remain open for 5 seconds
						horizontalPosition: 'center',
						verticalPosition: 'top',
					});
					this.router.navigate(['/profile']);
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
					console.log('Password Updation Form Handling Completed.');
				},
			});
		} else {
			console.log('Form is invalid');
			this.isLoading = false;
		}
	}

	toggleOldPasswordVisibility() {
		this.isOldPasswordVisible = !this.isOldPasswordVisible;
	}

	toggleNewPasswordVisibility() {
		this.isNewPasswordVisible = !this.isNewPasswordVisible;
	}

}
